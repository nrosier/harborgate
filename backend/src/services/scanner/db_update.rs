//! The production side of the daily database refresh (`specs/spinoff-local-scan.md`, sections 7
//! and 8; decisions 4, 28 and 29): the `db_update` job, its 24-hour schedule, the tool that runs
//! the scanner's own update command, and the store over the database.
//!
//! The pure flow (update, read the build time, compare, commit) is [`super::db_refresh`]. This
//! module supplies the real [`DatabaseTool`] and [`RefreshStore`] and the job around them.
//!
//! Process rules (section 7): the scanner is called by absolute path with an argument vector and
//! a cleared environment that holds the cache location and fixed settings only. No registry
//! string, token or secret is in an argument or the environment. The runner enforces the timeout,
//! the output cap and the process group kill. A failure stores one fixed text, never a tool
//! message.

use std::ffi::OsString;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tokio::sync::watch;

use super::db_refresh::{DatabaseTool, RefreshStore, RunTiming, refresh, run_error_text};
use super::process::Limits;
use super::steplog::{self, StepSlot};
use super::{Scanner, cache_dir, environment, temp_dir, update_args};
use crate::db::job_runs::{self, JobRun};
use crate::db::jobs::ClaimedJob;
use crate::db::{db_refresh as db, jobs};
use crate::error::{AppError, ScannerFault};
use crate::services::discovery::{MSG_BAD_PAYLOAD, fixed_text};
use crate::services::ids;
use crate::services::scan::queue::queue_scans_in;
use crate::services::scan::{ScanEnv, process_limits};
use crate::services::storage::repository::SqlStoreRepository;
use crate::worker::{JobOutcome, now_secs};

/// Time between schedule passes: once per 24 hours (decision 4; fixed, not operator-set).
pub const INTERVAL: Duration = Duration::from_secs(86_400);
/// Delay before the first pass after start.
const FIRST_DELAY: Duration = Duration::from_secs(120);

/// Both scanners, in the order their jobs are queued.
const SCANNERS: [Scanner; 2] = [Scanner::Trivy, Scanner::Grype];

/// The payload of a `db_update` job: the kind and the fixed scanner key. Nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbUpdatePayload {
    pub kind: String,
    pub scanner: String,
    /// `scheduled` for the daily pass (#360).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
}

impl DbUpdatePayload {
    pub fn new(scanner: Scanner) -> Self {
        Self {
            kind: "db_update".to_owned(),
            scanner: scanner.key().to_owned(),
            trigger: Some("scheduled".to_owned()),
        }
    }

    pub fn to_text(&self) -> Result<String, AppError> {
        serde_json::to_string(self).map_err(|_| AppError::InternalError)
    }
}

/// Queues one `db_update` job per scanner that has none open. Returns how many were queued. A
/// scanner whose previous job is still `queued` or `running` is skipped, so a slow update never
/// piles up jobs. A `failed` job does not stop the next day's job: the scanner must be able to
/// recover once the network does.
pub async fn schedule_once(pool: &SqlitePool, now: i64) -> Result<usize, AppError> {
    let mut queued = 0usize;
    for scanner in SCANNERS {
        let payload = DbUpdatePayload::new(scanner).to_text()?;
        if db::open_job_exists(pool, &payload).await? {
            continue;
        }
        let id = ids::new_id()?;
        jobs::enqueue(pool, &id, None, &payload, now).await?;
        queued += 1;
    }
    Ok(queued)
}

/// Runs [`schedule_once`] shortly after start and then every 24 hours, until `stop` turns true.
pub async fn run(pool: SqlitePool, stop: watch::Receiver<bool>) {
    run_every(FIRST_DELAY, INTERVAL, stop, || async {
        match schedule_once(&pool, now_secs()).await {
            Ok(queued) => tracing::info!(queued, "database update schedule pass finished"),
            Err(_) => tracing::warn!("database update schedule pass failed"),
        }
    })
    .await;
}

/// Calls `pass` after `first`, and then once every `every`, until `stop` turns true.
async fn run_every<F, Fut>(
    first: Duration,
    every: Duration,
    mut stop: watch::Receiver<bool>,
    mut pass: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut delay = first;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = stop.wait_for(|stopped| *stopped) => return,
        }
        pass().await;
        delay = every;
    }
}

/// Runs one `db_update` job. The refresh records its own `job_runs` row. A failure is a fixed
/// text and retries on the backoff, except a timeout or an oversized output, which cannot heal.
pub async fn run_db_update(pool: &SqlitePool, env: &ScanEnv, job: &ClaimedJob) -> JobOutcome {
    let Ok(payload) = serde_json::from_str::<DbUpdatePayload>(&job.payload) else {
        return JobOutcome::Permanent(MSG_BAD_PAYLOAD.to_owned());
    };
    let scanner = match payload.scanner.as_str() {
        "trivy" => Scanner::Trivy,
        "grype" => Scanner::Grype,
        _ => return JobOutcome::Permanent(MSG_BAD_PAYLOAD.to_owned()),
    };
    let limits = match process_limits(&SqlStoreRepository::new(pool.clone())).await {
        Ok(limits) => limits,
        Err(err) => return JobOutcome::Failed(fixed_text(&err)),
    };
    let tool = ProcessTool {
        pool: pool.clone(),
        env: env.clone(),
        limits,
        job_id: job.id.clone(),
        // The attempt this run belongs to: the worker counts the attempt that is running now.
        attempt: job.attempts + 1,
    };
    let store = SqlRefreshStore {
        pool: pool.clone(),
        job_id: job.id.clone(),
    };
    match refresh(&tool, &store, scanner, now_secs).await {
        Ok(outcome) => {
            tracing::info!(
                scanner = scanner.key(),
                ?outcome,
                "database refresh finished"
            );
            JobOutcome::Done
        }
        // The job's `last_error` is the same fixed text the run's `error_summary` holds.
        Err(err @ AppError::Scanner(ScannerFault::TimedOut | ScannerFault::OutputTooLarge)) => {
            JobOutcome::Permanent(run_error_text(&err).to_owned())
        }
        Err(err) => JobOutcome::Failed(run_error_text(&err).to_owned()),
    }
}

/// The scanner's own update command, run through the shared runner. Each step is recorded in
/// the job's log (#308); a step's stdout is stored, because an update step prints no report.
struct ProcessTool {
    pool: SqlitePool,
    env: ScanEnv,
    limits: Limits,
    job_id: String,
    attempt: i64,
}

impl ProcessTool {
    /// Runs one step and records it. `seq` is the step's place in the job attempt. The record is
    /// written whatever the outcome, and the step's own result is returned unchanged.
    async fn run_args(
        &self,
        scanner: Scanner,
        args: &[OsString],
        seq: i64,
    ) -> Result<Vec<u8>, AppError> {
        let vars = environment(self.env.cache_root(), scanner, false);
        let slot = StepSlot {
            job_id: &self.job_id,
            attempt: self.attempt,
            seq,
        };
        let started_at = now_secs();
        let command = format!("{} {}", scanner.key(), args_text(args));
        let step_id = steplog::begin(
            &self.pool,
            &slot,
            &command,
            started_at,
            self.limits.timeout.as_secs(),
        )
        .await;
        let (result, record) = self
            .env
            .run_scanner(scanner, args, &vars, self.limits, true)
            .await;
        steplog::finish(&self.pool, step_id.as_deref(), &record).await;
        result
    }
}

/// The argument text of a step, for the log. The arguments are fixed (no secret is in them).
fn args_text(args: &[OsString]) -> String {
    args.iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

impl DatabaseTool for ProcessTool {
    async fn update(&self, scanner: Scanner) -> Result<(), AppError> {
        let cache = cache_dir(self.env.cache_root(), scanner);
        std::fs::create_dir_all(&cache).map_err(|_| AppError::Scanner(ScannerFault::Failed))?;
        let tmp = temp_dir(self.env.cache_root(), scanner);
        std::fs::create_dir_all(&tmp).map_err(|_| AppError::Scanner(ScannerFault::Failed))?;
        // Trivy needs two downloads (the vulnerability database and the Java database). Both
        // must succeed. The output is discarded: it is never stored or logged.
        for (seq, args) in update_args(scanner).iter().enumerate() {
            let seq = i64::try_from(seq).unwrap_or(i64::MAX);
            self.run_args(scanner, args, seq).await?;
        }
        Ok(())
    }

    async fn built_at(&self, scanner: Scanner) -> Result<i64, AppError> {
        let unavailable = AppError::Scanner(ScannerFault::DatabaseNotAvailable);
        let text = match scanner {
            // Trivy keeps the build time in `db/metadata.json` (field `UpdatedAt`, verified
            // 2026-11-10 against v0.76.2).
            Scanner::Trivy => {
                let path = cache_dir(self.env.cache_root(), scanner).join("db/metadata.json");
                std::fs::read_to_string(path).map_err(|_| unavailable)?
            }
            // Grype has no build-time file. `grype db status -o json` prints it as `built`
            // (verified 2026-11-10 against v0.121.2).
            Scanner::Grype => {
                let args: Vec<OsString> =
                    vec!["db".into(), "status".into(), "-o".into(), "json".into()];
                // A status read, not an update step: it is not logged, and its stdout is the
                // build time only.
                let vars = environment(self.env.cache_root(), scanner, false);
                let (result, _record) = self
                    .env
                    .run_scanner(scanner, &args, &vars, self.limits, false)
                    .await;
                let body = result?;
                String::from_utf8(body).map_err(|_| unavailable)?
            }
        };
        parse_built_at(scanner, &text).ok_or(AppError::Scanner(ScannerFault::DatabaseNotAvailable))
    }
}

/// The build time in a Trivy `metadata.json` or a Grype `db status` JSON document, as Unix
/// seconds, or `None` when it is missing or not an RFC 3339 time.
pub(super) fn parse_built_at(scanner: Scanner, text: &str) -> Option<i64> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let field = match scanner {
        Scanner::Trivy => "UpdatedAt",
        Scanner::Grype => "built",
    };
    let when = value.get(field)?.as_str()?;
    crate::services::acceptance::parse_rfc3339(when)
}

/// The storage side of a refresh, over the pool.
struct SqlRefreshStore {
    pool: SqlitePool,
    job_id: String,
}

impl RefreshStore for SqlRefreshStore {
    async fn record_run(
        &self,
        scanner: Scanner,
        run: RunTiming,
        error: Option<&str>,
    ) -> Result<(), AppError> {
        job_runs::insert_for_job(
            &self.pool,
            &JobRun {
                id: ids::new_id()?,
                job_kind: "db_update".to_owned(),
                started_at: run.started_at,
                finished_at: Some(run.finished_at),
                status: if error.is_none() { "done" } else { "failed" }.to_owned(),
                processed_count: 0,
                error_summary: error.map(str::to_owned),
                scanner: Some(scanner.key().to_owned()),
            },
            &self.job_id,
        )
        .await
    }

    async fn stored_built_at(&self, scanner: Scanner) -> Result<Option<i64>, AppError> {
        db::stored_built_at(&self.pool, scanner.key()).await
    }

    async fn stored_platform_digests(&self) -> Result<Vec<String>, AppError> {
        db::stored_platform_digests(&self.pool).await
    }

    async fn commit_newer(
        &self,
        scanner: Scanner,
        built_at: i64,
        digests: &[String],
    ) -> Result<usize, AppError> {
        let now = now_secs();
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| AppError::InternalError)?;
        db::store_built_at(&mut tx, scanner.key(), built_at, now).await?;
        let mut queued = 0usize;
        for digest in digests {
            // Read in this transaction, so an image evicted since the list was taken is skipped.
            for platform_id in db::stored_platform_ids_with_digest(&mut tx, digest).await? {
                queued += queue_scans_in(
                    &mut tx,
                    &platform_id,
                    None,
                    "db_update",
                    Some(scanner.key()),
                    now,
                )
                .await?;
            }
        }
        tx.commit().await.map_err(|_| AppError::InternalError)?;
        Ok(queued)
    }
}

#[cfg(test)]
mod tests;
