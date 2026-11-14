//! The `scan` job and the convert step (`specs/spinoff-local-scan.md`, section 6 steps 4 and 5,
//! section 7, section 9; decisions 28, 29 and 19).
//!
//! A scan job carries ids, the scanner key and the image it is about ([`queue::ScanPayload`]). It runs the pinned scanner out of
//! process through [`ScannerRunner`] (absolute path, argument vector, cleared environment, the
//! process group killed on timeout, one process at a time), reads the output with the strict
//! parser, and stores the run in one `BEGIN IMMEDIATE` transaction: the run becomes `done`, its
//! findings are stored, and the merged `cve_findings` of every tag whose current image holds the
//! platform are recomputed ([`convert`]). Either all of it commits or none of it.
//!
//! A scan never downloads: Trivy runs with `--skip-db-update --skip-java-db-update`, Grype with
//! `GRYPE_DB_AUTO_UPDATE=false`, and a missing database fails the run before any process starts
//! (`scanner database not available`).
//!
//! Failure rules: a failed run records one fixed text (`scan_runs.error`, the job's `last_error`)
//! and is never `done`, so the merged view and the issue rules never read it. A failed scanner
//! or platform therefore never closes an issue (section 16): the issue rules hold a close open
//! until every enabled scanner has a `done` run for every platform of the newest image.
//! Timeouts, an oversized output and unreadable output cannot heal by retrying and fail the job
//! at once. A non-zero exit and a missing database are retried on the backoff.
//!
//! The publish step is `services::publish`. [`publish_ready`] is the hook that queues it: when a
//! run ends and no run or pull of its image is open, one `publish` job is queued for each source
//! whose newest image it is (section 6 steps 6 and 7).

pub mod convert;
pub mod queue;
#[cfg(test)]
mod tests;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sqlx::SqlitePool;

use crate::db::jobs::ClaimedJob;
use crate::db::scans as db;
use crate::error::{AppError, ScannerFault};
use crate::services::advisory_lookup::AdvisoryLookup;
use crate::services::discovery::{MSG_BAD_PAYLOAD, fixed_text};
use crate::services::jobs::MAX_ATTEMPTS;
use crate::services::publish;
use crate::services::scanner::parse::{self, Report};
use crate::services::scanner::process::{
    Invocation, Limits, ScannerRunner, StepOutcome, StepRecord,
};
use crate::services::scanner::selection::ScannerPrograms;
use crate::services::scanner::steplog::{self, StepSlot};
use crate::services::scanner::{Scanner, cache_dir, environment, scan_args, temp_dir};
use crate::services::storage::eviction;
use crate::services::storage::job::read_limits;
use crate::services::storage::limits::parse_positive_u64;
use crate::services::storage::messages::NO_LONGER_STORED;
use crate::services::storage::repository::{SqlStoreRepository, StoreRepository};
use crate::services::storage::{StoreRoot, checked_id};
use crate::worker::JobOutcome;

use queue::ScanPayload;

/// `scanner.timeout_s`: the timeout of one run in seconds (section 13).
pub const TIMEOUT_KEY: &str = "scanner.timeout_s";
/// `scanner.output_max_bytes`: the cap on one run's output (section 13).
pub const OUTPUT_MAX_KEY: &str = "scanner.output_max_bytes";

/// What the scan job needs besides the pool: the runner, the cache root and the scanner
/// selection (the bundled binaries, or a newer downloaded one, #390).
#[derive(Debug, Clone)]
pub struct ScanEnv {
    runner: ScannerRunner,
    cache_root: PathBuf,
    programs: Arc<ScannerPrograms>,
    advisory: AdvisoryLookup,
}

impl ScanEnv {
    /// The production setup: the scanner selection made at startup and the cache under
    /// `<data dir>/scanner-cache`.
    pub fn new(data_dir: &Path, programs: Arc<ScannerPrograms>) -> Self {
        Self {
            runner: ScannerRunner::new(),
            cache_root: data_dir.join("scanner-cache"),
            programs,
            // Tests that build the production setup have no network: no lookup is made.
            #[cfg(not(test))]
            advisory: AdvisoryLookup::live(),
            #[cfg(test)]
            advisory: AdvisoryLookup::off(),
        }
    }

    /// The production setup with the bundled executables only. Used by the tests.
    #[cfg(test)]
    pub fn under(data_dir: &Path) -> Self {
        Self::new(data_dir, Arc::new(ScannerPrograms::bundled(data_dir)))
    }

    /// A setup that calls other executables as the bundled ones. Used by the tests, with
    /// scripts. Nothing is downloaded.
    #[cfg(test)]
    pub fn with_programs(cache_root: PathBuf, trivy: PathBuf, grype: PathBuf) -> Self {
        let programs = ScannerPrograms::with_bundled_paths(&cache_root, trivy, grype);
        Self::with_selection(cache_root, Arc::new(programs))
    }

    /// A setup with a given scanner selection. Used by the tests.
    #[cfg(test)]
    pub fn with_selection(cache_root: PathBuf, programs: Arc<ScannerPrograms>) -> Self {
        Self {
            runner: ScannerRunner::new(),
            cache_root,
            programs,
            advisory: AdvisoryLookup::off(),
        }
    }

    /// The same setup with another advisory lookup. Used by the tests.
    #[cfg(test)]
    pub fn with_advisory(mut self, advisory: AdvisoryLookup) -> Self {
        self.advisory = advisory;
        self
    }

    /// Runs `scanner` with the selected binary, through the shared runner. When a downloaded
    /// binary does not start (the spawn fails), it is marked broken, the bundled binary is
    /// selected, and the run is made again with it (#390). A run that started and exited
    /// non-zero is a normal failure: it is returned as it is and changes no selection.
    pub(crate) async fn run_scanner(
        &self,
        scanner: Scanner,
        args: &[OsString],
        env: &[(OsString, OsString)],
        limits: Limits,
        log_stdout: bool,
    ) -> (Result<Vec<u8>, AppError>, StepRecord) {
        let (program, used) = self.programs.program(scanner);
        let attempt = self
            .runner
            .run_recorded(Invocation {
                program: &program,
                args,
                env,
                limits,
                log_stdout,
            })
            .await;
        if attempt.1.outcome != StepOutcome::SpawnFailed
            || !self.programs.launch_failed(scanner, used)
        {
            return attempt;
        }
        let (program, _) = self.programs.program(scanner);
        self.runner
            .run_recorded(Invocation {
                program: &program,
                args,
                env,
                limits,
                log_stdout,
            })
            .await
    }

    /// The root of the scanner caches.
    pub(crate) fn cache_root(&self) -> &Path {
        &self.cache_root
    }

    /// True when the scanner's database is in its cache. Without it a scan run fails before any
    /// process starts. Trivy keeps `db/trivy.db`; Grype keeps `<schema>/vulnerability.db`.
    fn database_present(&self, scanner: Scanner) -> bool {
        let cache = cache_dir(&self.cache_root, scanner);
        match scanner {
            Scanner::Trivy => cache.join("db").join("trivy.db").is_file(),
            Scanner::Grype => std::fs::read_dir(&cache)
                .map(|entries| {
                    entries
                        .flatten()
                        .any(|entry| entry.path().join("vulnerability.db").is_file())
                })
                .unwrap_or(false),
        }
    }
}

/// The timeout and output cap of one scanner process, from the operator settings or the defaults
/// (section 13). A database refresh uses the same limits as a scan. A stored timeout is clamped to
/// the range the settings API enforces, so a bad stored value cannot give a near-zero or an
/// unbounded run.
pub(crate) async fn process_limits<R: StoreRepository>(repo: &R) -> Result<Limits, AppError> {
    let (min, max) = crate::services::scan_settings::TIMEOUT_RANGE;
    let timeout = parse_positive_u64(
        repo.setting(TIMEOUT_KEY).await?.as_deref(),
        crate::services::scanner::process::DEFAULT_TIMEOUT.as_secs(),
    )
    .clamp(min, max);
    let output_max = parse_positive_u64(
        repo.setting(OUTPUT_MAX_KEY).await?.as_deref(),
        crate::services::scanner::process::DEFAULT_OUTPUT_MAX_BYTES,
    );
    Ok(Limits {
        timeout: Duration::from_secs(timeout),
        output_max_bytes: output_max,
    })
}

/// How a scan attempt stopped short of `done`.
enum Stop {
    /// The job fails now, with no retry.
    Permanent(String),
    /// The job fails and retries on the backoff.
    Retry(String),
    /// The run is `done` already: nothing to do.
    AlreadyDone,
}

/// Runs one `scan` job.
pub async fn run_scan(
    pool: &SqlitePool,
    env: &ScanEnv,
    store: &StoreRoot,
    job: &ClaimedJob,
    now: i64,
) -> JobOutcome {
    let Ok(payload) = serde_json::from_str::<ScanPayload>(&job.payload) else {
        return JobOutcome::Permanent(MSG_BAD_PAYLOAD.to_owned());
    };
    let scanner = match payload.scanner.as_str() {
        "trivy" => Scanner::Trivy,
        "grype" => Scanner::Grype,
        _ => return JobOutcome::Permanent(MSG_BAD_PAYLOAD.to_owned()),
    };
    if checked_id(&payload.run_id).is_err() || checked_id(&payload.platform_id).is_err() {
        return JobOutcome::Permanent(MSG_BAD_PAYLOAD.to_owned());
    }
    let slot = StepSlot {
        job_id: &job.id,
        attempt: job.attempts + 1,
        seq: 0,
    };
    match scan_once(pool, env, store, &payload, scanner, &slot, now).await {
        Ok(()) => JobOutcome::Done,
        Err(Stop::AlreadyDone) => JobOutcome::DoneWithNote("already scanned".to_owned()),
        Err(Stop::Permanent(text)) => JobOutcome::Permanent(text),
        Err(Stop::Retry(text)) => JobOutcome::Failed(text),
    }
}

fn internal(_: AppError) -> Stop {
    Stop::Retry(fixed_text(&AppError::InternalError))
}

/// Maps a scanner fault to the way the job stops.
fn stop_for(fault: ScannerFault) -> Stop {
    let text = fault.text().to_owned();
    match fault {
        ScannerFault::TimedOut
        | ScannerFault::OutputTooLarge
        | ScannerFault::OutputNotRecognised => Stop::Permanent(text),
        ScannerFault::Failed | ScannerFault::DatabaseNotAvailable => Stop::Retry(text),
    }
}

/// Records the end of an attempt with a fixed text, and returns how the job stops. A run whose
/// job will retry goes back to `queued` with the text kept (`last` is false), so it still holds
/// its image against eviction and the image is not yet "all scans ended". The last attempt, and
/// a failure that cannot heal, end the run as `failed`. A failure to record is logged without
/// detail, and the stop is still returned.
async fn fail_run(
    pool: &SqlitePool,
    run_id: &str,
    text: &str,
    now: i64,
    last: bool,
    stop: Stop,
) -> Stop {
    let retrying = matches!(stop, Stop::Retry(_)) && !last;
    let recorded = async {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        if retrying {
            db::release_run(&mut conn, run_id, text).await
        } else {
            db::finish_failed(&mut conn, run_id, text, now).await
        }
    }
    .await;
    if recorded.is_err() {
        tracing::warn!("could not record the end of a failed scan run");
    }
    stop
}

async fn scan_once(
    pool: &SqlitePool,
    env: &ScanEnv,
    store: &StoreRoot,
    payload: &ScanPayload,
    scanner: Scanner,
    slot: &StepSlot<'_>,
    now: i64,
) -> Result<(), Stop> {
    let run_id = payload.run_id.as_str();
    let run = {
        let mut conn = pool
            .acquire()
            .await
            .map_err(|_| Stop::Retry(fixed_text(&AppError::InternalError)))?;
        let found = db::find_run(&mut conn, run_id).await.map_err(internal)?;
        let Some(run) = found else {
            return Err(Stop::Permanent(MSG_BAD_PAYLOAD.to_owned()));
        };
        if run.image_platform_id != payload.platform_id || run.scanner != payload.scanner {
            return Err(Stop::Permanent(MSG_BAD_PAYLOAD.to_owned()));
        }
        match run.status.as_str() {
            "done" => return Err(Stop::AlreadyDone),
            // A retry of a failed job, or a run a stopped process left `running`.
            "failed" | "running" => {
                db::requeue_run(&mut conn, run_id).await.map_err(internal)?;
            }
            _ => {}
        }
        run
    };

    let repo = SqlStoreRepository::new(pool.clone());
    let limits = read_limits(&repo).await.map_err(internal)?;
    // The run moves to `running` only while its image is `stored`, in one statement, so an
    // eviction and a scan start cannot interleave (section 4).
    let started = repo
        .start_scan(run_id, &payload.platform_id, now)
        .await
        .map_err(internal)?;
    let layout = store.layout_dir(&payload.platform_id).map_err(internal)?;
    if !started || !layout.is_dir() {
        return Err(fail_run(
            pool,
            run_id,
            NO_LONGER_STORED,
            now,
            true,
            Stop::Permanent(NO_LONGER_STORED.to_owned()),
        )
        .await);
    }

    // `slot.attempt` is this attempt's number (the attempts already made, plus one).
    let last = slot.attempt >= MAX_ATTEMPTS;
    let outcome = scan_and_store(pool, env, &repo, &run, &layout, scanner, (now, last, slot)).await;
    // The store may be over its maximum while this run held its image. The check runs again when
    // a scan run ends (section 4), whatever the outcome.
    match eviction::enforce(&repo, store, limits.max_stored, None, now).await {
        Ok(_) => {}
        Err(_) => tracing::warn!("eviction after a scan run did not complete"),
    }
    // A run that ended, whatever its outcome, may be the last open run of its image: a failed
    // run does not hold the SARIF back (section 6 step 6). A run that will retry is `queued`
    // again, so it keeps the image open.
    match publish_ready(pool, &run.image_id, now).await {
        Ok(true) => tracing::info!("every scan of an image has ended"),
        Ok(false) => {}
        Err(_) => tracing::warn!("could not check whether the scans of an image ended"),
    }
    if outcome.is_err() {
        tracing::warn!("a scan run failed");
    }
    outcome
}

/// The part of a scan from the process to the commit. A failure ends the run as `failed`.
async fn scan_and_store(
    pool: &SqlitePool,
    env: &ScanEnv,
    repo: &SqlStoreRepository,
    run: &db::RunRow,
    layout: &Path,
    scanner: Scanner,
    (now, last, slot): (i64, bool, &StepSlot<'_>),
) -> Result<(), Stop> {
    let run_id = run.id.as_str();
    let fail =
        |fault: ScannerFault| fail_run(pool, run_id, fault.text(), now, last, stop_for(fault));

    if !env.database_present(scanner) {
        return Err(fail(ScannerFault::DatabaseNotAvailable).await);
    }
    let process_limits = process_limits(repo).await.map_err(internal)?;
    let args: Vec<OsString> = scan_args(scanner, layout);
    // The child's TMPDIR must exist before it starts. A scan run does not go through the update.
    if std::fs::create_dir_all(temp_dir(&env.cache_root, scanner)).is_err() {
        return Err(fail(ScannerFault::Failed).await);
    }
    let vars = environment(&env.cache_root, scanner, true);
    // The step's log (#308): its stderr tail, redacted. A scan's stdout is the report, so it is
    // returned to the parser below and never stored as a log line.
    let started_at = crate::worker::now_secs();
    let command = format!("{} scan", scanner.key());
    let step_id = steplog::begin(
        pool,
        slot,
        &command,
        started_at,
        process_limits.timeout.as_secs(),
    )
    .await;
    let (result, record) = env
        .run_scanner(scanner, &args, &vars, process_limits, false)
        .await;
    steplog::finish(pool, step_id.as_deref(), &record).await;
    let body = match result {
        Ok(body) => body,
        Err(AppError::Scanner(fault)) => return Err(fail(fault).await),
        Err(_) => return Err(fail(ScannerFault::Failed).await),
    };
    let report = match parse_report(scanner, body).await {
        Ok(report) => report,
        Err(fault) => return Err(fail(fault).await),
    };

    // The GHSA and GO ids with no CVE id are looked up before the transaction opens, so no
    // network call runs inside it. A failed lookup changes nothing (#379).
    env.advisory.resolve(pool, &report.findings, now).await;

    let built_at = {
        let mut conn = pool
            .acquire()
            .await
            .map_err(|_| internal(AppError::InternalError))?;
        db::database_built_at(&mut conn, scanner.key())
            .await
            .map_err(internal)?
    };
    let finished = crate::worker::now_secs().max(now);
    match store_run(pool, run, &report, built_at, finished).await {
        Ok(()) => Ok(()),
        Err(_) => {
            // The transaction rolled back, so nothing of the run was stored. The job retries.
            Err(fail_run(
                pool,
                run_id,
                ScannerFault::Failed.text(),
                finished,
                last,
                Stop::Retry(fixed_text(&AppError::InternalError)),
            )
            .await)
        }
    }
}

/// Parses off the async threads: a 64 MiB report takes real CPU time.
async fn parse_report(scanner: Scanner, body: Vec<u8>) -> Result<Report, ScannerFault> {
    let parsed = tokio::task::spawn_blocking(move || match scanner {
        Scanner::Trivy => parse::parse_trivy(&body),
        Scanner::Grype => parse::parse_grype(&body),
    })
    .await;
    match parsed {
        Ok(Ok(report)) => Ok(report),
        Ok(Err(AppError::Scanner(fault))) => Err(fault),
        Ok(Err(_)) | Err(_) => Err(ScannerFault::OutputNotRecognised),
    }
}

/// Stores a finished run and recomputes the merged findings, in one `BEGIN IMMEDIATE`
/// transaction.
async fn store_run(
    pool: &SqlitePool,
    run: &db::RunRow,
    report: &Report,
    built_at: Option<i64>,
    finished: i64,
) -> Result<(), AppError> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    db::finish_done(
        &mut tx,
        &run.id,
        &report.scanner_version,
        built_at,
        finished,
    )
    .await?;
    let findings = canonical_findings(&mut tx, &report.findings).await?;
    for finding in &findings {
        db::insert_finding(
            &mut tx,
            &run.id,
            &db::NewFinding {
                cve_id: &finding.cve_id,
                package: &finding.package,
                version: finding.version.as_deref(),
                fixed_in_version: finding.fixed_in_version.as_deref(),
                severity: finding.severity,
                cvss_v3: finding.cvss_v3,
                description: finding.description.as_deref(),
                alias: finding.alias.as_deref(),
            },
        )
        .await?;
    }
    convert::recompute_image(&mut tx, &run.image_id, finished).await?;
    tx.commit().await.map_err(|_| AppError::InternalError)
}

/// The findings of a run under their primary ids (#337). A finding the parser already gave a CVE
/// id and an alias records the pair in `vulnerability_aliases`. A non-CVE id with no alias (a
/// Trivy GHSA id) takes the primary id recorded for it, and keeps its own id as the alias. A
/// GHSA-only id with no record stays as it is. The result is merged by (id, package) again, as
/// two ids can now name one CVE.
async fn canonical_findings(
    conn: &mut sqlx::SqliteConnection,
    findings: &[parse::Finding],
) -> Result<Vec<parse::Finding>, AppError> {
    let mut out = Vec::with_capacity(findings.len());
    for finding in findings {
        let mut finding = finding.clone();
        if finding.alias.as_deref() == Some(finding.cve_id.as_str()) {
            finding.alias = None;
        }
        match finding.alias.as_deref() {
            Some(alias) if parse::is_cve_id(&finding.cve_id) => {
                db::record_alias(conn, alias, &finding.cve_id).await?;
            }
            Some(_) => {}
            None if !parse::is_cve_id(&finding.cve_id) => {
                if let Some(primary) = db::alias_primary(conn, &finding.cve_id).await?
                    && primary != finding.cve_id
                {
                    finding.alias = Some(std::mem::replace(&mut finding.cve_id, primary));
                }
            }
            None => {}
        }
        out.push(finding);
    }
    Ok(parse::merge_findings(out))
}

/// The publish hook. True when no run of any platform of `image_id` is `queued` or `running`
/// and no platform of it still waits for its pull: every scan of the image has ended, whatever
/// its outcome. When it is true, one `publish` job is queued for each source whose newest image
/// this is (section 6 steps 6 and 7; [`publish::queue_publish`]). A job already open for the same
/// source and image is not queued again.
pub async fn publish_ready(pool: &SqlitePool, image_id: &str, now: i64) -> Result<bool, AppError> {
    let ready = {
        let mut conn = pool.acquire().await.map_err(|_| AppError::InternalError)?;
        !db::image_has_open_runs(&mut conn, image_id).await?
            && !crate::db::publish::image_has_pending_pull(&mut conn, image_id).await?
    };
    if ready {
        publish::queue_publish(pool, image_id, now).await?;
    }
    Ok(ready)
}
