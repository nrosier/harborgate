//! Tests of the scan job and the convert step against the real migrated schema
//! (`specs/spinoff-local-scan.md`, section 16, scanners). The scanners are shell scripts that
//! stand in for the pinned executables: they record their argument vector and environment, and
//! print the reports captured from the real Trivy and Grype in #281.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sqlx::SqlitePool;

use super::queue::queue_scans;
use super::*;
use crate::db;
use crate::db::jobs::ClaimedJob;
use crate::services::issue_lifecycle::test_support::{FakeGithub, FakeIssues};
use crate::services::merged_view;
use crate::worker::JobOutcome;

const TRIVY_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/scanner/trivy-layout.json"
);
const GRYPE_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/scanner/grype-layout.json"
);

const IMG_OLD: &str = "000000000000000000000000000000a1";
const IMG_NEW: &str = "000000000000000000000000000000a2";
const P_OLD: &str = "000000000000000000000000000000b1";
const P_NEW: &str = "000000000000000000000000000000b2";
const P_ARM: &str = "000000000000000000000000000000b3";
const NOW: i64 = 1_800_000_000;

/// A parent variable no child may see, and that no stored text may hold.
const CANARY_VAR: &str = "DOCKWARD_ENCRYPTION_KEY";
const CANARY: &str = "canary-secret-7f3a9";

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fx {
    pool: SqlitePool,
    dir: PathBuf,
    env: ScanEnv,
    store: StoreRoot,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    if let Err(err) = std::fs::write(&path, format!("#!/bin/sh\n{body}\n")) {
        panic!("script: {err}");
    }
    if let Err(err) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)) {
        panic!("chmod: {err}");
    }
    path
}

/// A scanner script that records its arguments and environment next to itself, then prints
/// `report` (a file path).
fn recording(dir: &Path, name: &str, report: &str) -> String {
    let log = dir.join(format!("{name}.argv"));
    let envlog = dir.join(format!("{name}.env"));
    format!(
        "printf '%s\\n' \"$@\" > '{}'\nexport -p > '{}'\ncat '{report}'",
        log.display(),
        envlog.display()
    )
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

async fn exec(pool: &SqlitePool, sql: &'static str, binds: &[&str]) {
    let mut query = sqlx::query(sql);
    for bind in binds {
        query = query.bind(*bind);
    }
    if let Err(err) = query.execute(pool).await {
        panic!("test sql: {err}");
    }
}

async fn count(pool: &SqlitePool, sql: &'static str, binds: &[&str]) -> i64 {
    let mut query = sqlx::query_scalar::<_, i64>(sql);
    for bind in binds {
        query = query.bind(*bind);
    }
    match query.fetch_one(pool).await {
        Ok(value) => value,
        Err(err) => panic!("count: {err}"),
    }
}

impl Fx {
    /// A migrated database; source `s1` on `ghcr.io/o/app` targeting `octo/app` with automatic
    /// issues for CRITICAL; the image `IMG_OLD` with one stored platform `P_OLD` under tag `v1`;
    /// both scanner databases present. `trivy` and `grype` are the script bodies.
    async fn new(name: &str, trivy: &str, grype: &str) -> Self {
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("dockward-scan-{name}-{}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(err) = std::fs::create_dir_all(&dir) {
            panic!("dir: {err}");
        }
        let pool = match db::open(&dir).await {
            Ok(pool) => pool,
            Err(err) => panic!("db: {err:?}"),
        };
        for sql in [
            "INSERT INTO users (id, username, password_hash, role, token_version)
             VALUES ('u1', 'u1', NULL, 'user', 0)",
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('c1', 'u1', 'g', 'v1:fake')",
            "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id,
                 github_owner, github_repo, auto_create_issues, min_issue_severity)
             VALUES ('s1', 'u1', 'hub-default-ghcr', 'o/app', '*', 'c1', 'octo', 'app', 1, 'CRITICAL')",
        ] {
            exec(&pool, sql, &[]).await;
        }
        let bin = dir.join("bin");
        let cache = dir.join("scanner-cache");
        for path in [bin.clone(), cache.join("trivy/db"), cache.join("grype/6")] {
            if let Err(err) = std::fs::create_dir_all(&path) {
                panic!("dir: {err}");
            }
        }
        for file in [
            cache.join("trivy/db/trivy.db"),
            cache.join("grype/6/vulnerability.db"),
        ] {
            if let Err(err) = std::fs::write(&file, b"db") {
                panic!("db file: {err}");
            }
        }
        let trivy = write_script(&bin, "trivy", trivy);
        let grype = write_script(&bin, "grype", grype);
        let store = StoreRoot::at(dir.join("images"));
        let fx = Self {
            pool,
            dir,
            env: ScanEnv::with_programs(cache, trivy, grype),
            store,
        };
        fx.image(IMG_OLD, "sha256:old").await;
        fx.platform(P_OLD, IMG_OLD, "linux/amd64").await;
        fx.observe("v1", IMG_OLD, 100).await;
        fx
    }

    fn bin(&self) -> PathBuf {
        self.dir.join("bin")
    }

    /// Replaces a scanner script.
    fn script(&self, name: &str, body: &str) {
        write_script(&self.bin(), name, body);
    }

    async fn image(&self, id: &str, digest: &str) {
        exec(
            &self.pool,
            "INSERT INTO images (id, hub_id, repository, digest, is_index)
             VALUES (?, 'hub-default-ghcr', 'o/app', ?, 1)",
            &[id, digest],
        )
        .await;
    }

    /// A stored platform with its layout directory.
    async fn platform(&self, id: &str, image: &str, platform: &str) {
        exec(
            &self.pool,
            "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state, pulled_at)
             VALUES (?, ?, ?, ?, 'stored', 1)",
            &[id, image, platform, &format!("sha256:{id}")],
        )
        .await;
        let layout = self.store.root().join(id);
        if let Err(err) = std::fs::create_dir_all(&layout) {
            panic!("layout: {err}");
        }
        if let Err(err) = std::fs::write(layout.join("index.json"), b"{}") {
            panic!("index: {err}");
        }
    }

    async fn observe(&self, tag: &str, image: &str, first_seen: i64) {
        let at = first_seen.to_string();
        exec(
            &self.pool,
            "INSERT INTO tag_observations (source_id, tag, image_id, first_seen_at, last_seen_at)
             VALUES ('s1', ?, ?, ?, ?)",
            &[tag, image, &at, &at],
        )
        .await;
    }

    async fn queue(&self, platform: &str) -> usize {
        match queue_scans(&self.pool, platform, Some("s1"), "first_pull", NOW).await {
            Ok(queued) => queued,
            Err(err) => panic!("queue: {err:?}"),
        }
    }

    /// Claims and runs every due scan job, and returns the outcomes in order.
    async fn drain(&self) -> Vec<(String, JobOutcome)> {
        let mut outcomes = Vec::new();
        loop {
            let claimed = match crate::db::jobs::claim_next(&self.pool, NOW + 10_000).await {
                Ok(job) => job,
                Err(err) => panic!("claim: {err:?}"),
            };
            let Some(job) = claimed else {
                break;
            };
            // The publish hook queues a `publish` job when an image's scans end. It has its own
            // tests (`services::publish`); here it is only marked done.
            if job.payload.contains(r#""kind":"publish""#) {
                if let Err(err) = crate::db::jobs::mark_done(&self.pool, &job.id, NOW).await {
                    panic!("mark publish: {err:?}");
                }
                continue;
            }
            let scanner = serde_json::from_str::<ScanPayload>(&job.payload)
                .map(|payload| payload.scanner)
                .unwrap_or_default();
            let outcome = run_scan(&self.pool, &self.env, &self.store, &job, NOW).await;
            let finished = match &outcome {
                JobOutcome::Done | JobOutcome::DoneWithNote(_) | JobOutcome::DoneEmpty(_) => {
                    crate::db::jobs::mark_done(&self.pool, &job.id, NOW).await
                }
                JobOutcome::Failed(text) | JobOutcome::Permanent(text) => {
                    let mut conn = match self.pool.acquire().await {
                        Ok(conn) => conn,
                        Err(err) => panic!("conn: {err}"),
                    };
                    crate::db::jobs::record_failure(
                        &mut conn,
                        &job.id,
                        job.attempts + 1,
                        None,
                        text,
                        true,
                        NOW,
                    )
                    .await
                }
                JobOutcome::Deferred { .. } => Ok(()),
            };
            if let Err(err) = finished {
                panic!("record: {err:?}");
            }
            outcomes.push((scanner, outcome));
        }
        outcomes
    }

    /// `(scanner, status, error)` of every run of a platform, oldest first.
    async fn runs(&self, platform: &str) -> Vec<(String, String, Option<String>)> {
        match sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT scanner, status, error FROM scan_runs WHERE image_platform_id = ?
             ORDER BY rowid",
        )
        .bind(platform)
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => rows,
            Err(err) => panic!("runs: {err}"),
        }
    }

    /// `(cve_id, package, severity, status)` of the tag's rows.
    async fn tag_rows(&self, tag: &str) -> Vec<(String, Option<String>, String, String)> {
        match sqlx::query_as::<_, (String, Option<String>, String, String)>(
            "SELECT cve_id, package, severity, status FROM cve_findings
             WHERE source_id = 's1' AND image_tag = ? ORDER BY cve_id",
        )
        .bind(tag)
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => rows,
            Err(err) => panic!("tag rows: {err}"),
        }
    }

    async fn merged(&self, image: &str) -> merged_view::MergedDigest {
        match merged_view::load(&self.pool, image).await {
            Ok(view) => view,
            Err(err) => panic!("merged: {err:?}"),
        }
    }
}

fn ok_scripts(dir_hint: &str) -> (String, String) {
    let _ = dir_hint;
    (
        format!("cat '{TRIVY_FIXTURE}'"),
        format!("cat '{GRYPE_FIXTURE}'"),
    )
}

fn outcomes_only(list: &[(String, JobOutcome)]) -> Vec<(&str, &JobOutcome)> {
    list.iter().map(|(s, o)| (s.as_str(), o)).collect()
}

/// Both scanners run on the captured reports: two done runs, their findings stored, and the
/// tag's merged rows. CVE-2026-4738 in zlib is reported by both and merges into one finding.
#[tokio::test]
async fn both_scanners_run_and_findings_merge_on_cve_and_package() {
    let (trivy, grype) = ok_scripts("");
    let fx = Fx::new("merge", &trivy, &grype).await;
    assert_eq!(fx.queue(P_OLD).await, 2);
    let outcomes = fx.drain().await;
    assert_eq!(
        outcomes_only(&outcomes),
        vec![("grype", &JobOutcome::Done), ("trivy", &JobOutcome::Done)]
    );
    assert_eq!(
        fx.runs(P_OLD).await,
        vec![
            ("grype".to_owned(), "done".to_owned(), None),
            ("trivy".to_owned(), "done".to_owned(), None)
        ]
    );
    let versions = count(
        &fx.pool,
        "SELECT COUNT(*) FROM scan_runs WHERE scanner_version IS NOT NULL AND finished_at IS NOT NULL",
        &[],
    )
    .await;
    assert_eq!(versions, 2, "the scanner version is stored with every run");

    let view = fx.merged(IMG_OLD).await;
    let zlib = view
        .findings
        .iter()
        .find(|f| f.cve_id == "CVE-2026-4738" && f.package == "zlib");
    let Some(zlib) = zlib else {
        panic!("zlib finding missing: {view:?}");
    };
    let names: Vec<&str> = zlib.scanners.iter().map(|s| s.key.as_str()).collect();
    assert_eq!(names, vec!["grype", "trivy"]);
    // Grype says Critical and Trivy Medium: the merged severity is the highest.
    assert_eq!(zlib.severity, "CRITICAL");
    assert_eq!(
        view.findings
            .iter()
            .filter(|f| f.cve_id == "CVE-2026-4738" && f.package == "zlib")
            .count(),
        1
    );

    let rows = fx.tag_rows("v1").await;
    let ids: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    assert!(
        ids.contains(&"CVE-2026-4738") && ids.contains(&"CVE-2025-60876"),
        "{rows:?}"
    );
    assert!(rows.iter().all(|r| r.3 == "open"));
    let zlib_row = rows.iter().find(|r| r.0 == "CVE-2026-4738");
    assert_eq!(
        zlib_row.map(|r| (r.1.as_deref(), r.2.as_str())),
        Some((Some("zlib"), "CRITICAL"))
    );
}

/// A multi-platform image: findings are stored per platform and merged for the tag, with the
/// platforms on the merged finding.
#[tokio::test]
async fn platforms_are_scanned_separately_and_merged_for_the_tag() {
    let (trivy, grype) = ok_scripts("");
    let fx = Fx::new("platforms", &trivy, &grype).await;
    fx.platform(P_ARM, IMG_OLD, "linux/arm64").await;
    fx.queue(P_OLD).await;
    fx.queue(P_ARM).await;
    let outcomes = fx.drain().await;
    assert_eq!(outcomes.len(), 4);
    assert!(outcomes.iter().all(|(_, o)| *o == JobOutcome::Done));
    let view = fx.merged(IMG_OLD).await;
    let zlib = view.findings.iter().find(|f| f.cve_id == "CVE-2026-4738");
    assert_eq!(
        zlib.map(|f| f.platforms.clone()),
        Some(vec!["linux/amd64".to_owned(), "linux/arm64".to_owned()])
    );
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM cve_findings WHERE cve_id = 'CVE-2026-4738'",
            &[]
        )
        .await,
        1,
        "one row per (source, tag, CVE)"
    );
}

/// A Trivy report with a SchemaVersion other than 2 fails the run with the fixed error, at once.
#[tokio::test]
async fn a_trivy_schema_version_other_than_2_fails_with_the_fixed_error() {
    let fx = Fx::new("schema", "", &format!("cat '{GRYPE_FIXTURE}'")).await;
    let bad = fx.dir.join("bad.json");
    let text =
        read(Path::new(TRIVY_FIXTURE)).replacen("\"SchemaVersion\": 2", "\"SchemaVersion\": 3", 1);
    assert!(text.contains("\"SchemaVersion\": 3"));
    if let Err(err) = std::fs::write(&bad, text) {
        panic!("write: {err}");
    }
    fx.script("trivy", &format!("cat '{}'", bad.display()));
    fx.queue(P_OLD).await;
    let outcomes = fx.drain().await;
    assert_eq!(
        outcomes_only(&outcomes),
        vec![
            ("grype", &JobOutcome::Done),
            (
                "trivy",
                &JobOutcome::Permanent("scanner output not recognised".to_owned())
            )
        ]
    );
    assert_eq!(
        fx.runs(P_OLD).await[1],
        (
            "trivy".to_owned(),
            "failed".to_owned(),
            Some("scanner output not recognised".to_owned())
        )
    );
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM scanner_findings f JOIN scan_runs r ON r.id = f.run_id
             WHERE r.scanner = 'trivy'",
            &[]
        )
        .await,
        0,
        "a failed run stores no findings"
    );
}

/// The timeout kills the process group and fails the run with `scanner timed out`.
#[tokio::test]
async fn the_timeout_kills_the_run_and_fails_it_with_the_fixed_text() {
    let fx = Fx::new("timeout", "", "").await;
    let pidfile = fx.dir.join("grandchild.pid");
    fx.script(
        "trivy",
        &format!(
            "/bin/sleep 60 &\necho $! > '{}'\n/bin/sleep 60",
            pidfile.display()
        ),
    );
    exec(
        &fx.pool,
        "INSERT INTO system_config (key, value) VALUES ('scanner.timeout_s', '3'), ('scanners.enabled', 'trivy')",
        &[],
    )
    .await;
    fx.queue(P_OLD).await;
    let started = std::time::Instant::now();
    let outcomes = fx.drain().await;
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(
        outcomes_only(&outcomes),
        vec![(
            "trivy",
            &JobOutcome::Permanent("scanner timed out".to_owned())
        )]
    );
    assert_eq!(
        fx.runs(P_OLD).await,
        vec![(
            "trivy".to_owned(),
            "failed".to_owned(),
            Some("scanner timed out".to_owned())
        )]
    );
    // Under heavy load the shell may not have started its grandchild before the timeout; then
    // there is nothing left to kill. The strict group-kill check is in the runner's own tests
    // (`scanner::process::tests::a_timeout_kills_the_whole_process_group`).
    let pid = read(&pidfile).trim().parse::<i32>().unwrap_or(0);
    if pid <= 0 {
        return;
    }
    let mut gone = false;
    for _ in 0..100 {
        if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err() {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(gone, "the process group is killed on timeout");
}

/// Output over the cap fails the run with `scanner output too large`.
#[tokio::test]
async fn the_output_cap_fails_the_run_with_the_fixed_text() {
    let (_, grype) = ok_scripts("");
    let fx = Fx::new("cap", "", &grype).await;
    exec(
        &fx.pool,
        "INSERT INTO system_config (key, value) VALUES ('scanner.output_max_bytes', '1024'), ('scanners.enabled', 'grype')",
        &[],
    )
    .await;
    fx.queue(P_OLD).await;
    let outcomes = fx.drain().await;
    assert_eq!(
        outcomes_only(&outcomes),
        vec![(
            "grype",
            &JobOutcome::Permanent("scanner output too large".to_owned())
        )]
    );
    assert_eq!(
        fx.runs(P_OLD).await[0].2.as_deref(),
        Some("scanner output too large")
    );
}

/// A missing database fails the run before any process starts: nothing is downloaded.
#[tokio::test]
async fn a_missing_database_fails_before_the_scanner_starts() {
    let fx = Fx::new("nodb", "", "").await;
    let marker = fx.dir.join("started");
    fx.script("grype", &format!("touch '{}'", marker.display()));
    if let Err(err) = std::fs::remove_dir_all(fx.dir.join("scanner-cache/grype")) {
        panic!("rm: {err}");
    }
    exec(
        &fx.pool,
        "INSERT INTO system_config (key, value) VALUES ('scanners.enabled', 'grype')",
        &[],
    )
    .await;
    fx.queue(P_OLD).await;
    let outcomes = fx.drain().await;
    assert_eq!(
        outcomes_only(&outcomes),
        vec![(
            "grype",
            &JobOutcome::Failed("scanner database not available".to_owned())
        )]
    );
    assert!(!marker.exists(), "the scanner never started");
}

/// The process rules: the absolute program path, the verified argument vector (offline flags),
/// and a cleared environment with the fixed allow-list only. A parent variable is absent in the
/// child. No secret reaches a run row, a job row or a log line.
#[test]
fn the_scanner_process_gets_the_verified_flags_and_a_cleared_environment() {
    let _guard = match crate::services::scanner::process::tests::ENV_LOCK.lock() {
        Ok(guard) => guard,
        Err(poison) => poison.into_inner(),
    };
    // SAFETY: ENV_LOCK serialises environment changes in this test binary; the variable is
    // removed before any assertion.
    unsafe { std::env::set_var(CANARY_VAR, CANARY) };
    let logs = LogSink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => panic!("runtime: {err}"),
    };
    let checked = tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            let fx = Fx::new("process", "", "").await;
            let bin = fx.bin();
            fx.script("trivy", &recording(&bin, "trivy", TRIVY_FIXTURE));
            fx.script("grype", &recording(&bin, "grype", GRYPE_FIXTURE));
            fx.queue(P_OLD).await;
            let outcomes = fx.drain().await;
            let first = (
                read(&bin.join("trivy.argv")),
                read(&bin.join("trivy.env")),
                read(&bin.join("grype.argv")),
                read(&bin.join("grype.env")),
            );

            // A failing scanner that prints the secret on stderr and stdout.
            fx.script(
                "grype",
                &format!("echo \"token={CANARY} ${CANARY_VAR}\" >&2\necho \"{CANARY}\"\nexit 1"),
            );
            fx.platform(P_ARM, IMG_OLD, "linux/arm64").await;
            fx.queue(P_ARM).await;
            let failed = fx.drain().await;

            let rows: Vec<String> = match sqlx::query_scalar::<_, String>(
                "SELECT COALESCE(error, '') || ' ' || COALESCE(scanner_version, '') FROM scan_runs
                 UNION ALL
                 SELECT payload || ' ' || COALESCE(last_error, '') FROM jobs",
            )
            .fetch_all(&fx.pool)
            .await
            {
                Ok(rows) => rows,
                Err(err) => panic!("rows: {err}"),
            };
            let layout = fx.store.root().join(P_OLD);
            (
                outcomes,
                failed,
                rows,
                first,
                layout,
                fx.dir.join("scanner-cache"),
            )
        })
    });
    unsafe { std::env::remove_var(CANARY_VAR) };
    let (outcomes, failed, rows, first, layout, cache) = checked;
    let (trivy_argv, trivy_env, grype_argv, grype_env) = first;

    assert!(
        outcomes.iter().all(|(_, o)| *o == JobOutcome::Done),
        "{outcomes:?}"
    );
    let layout = layout.display().to_string();
    assert_eq!(
        trivy_argv.lines().collect::<Vec<_>>(),
        vec![
            "image",
            "--input",
            layout.as_str(),
            "--format",
            "json",
            "--skip-db-update",
            "--skip-java-db-update"
        ]
    );
    let source = format!("oci-dir:{layout}");
    assert_eq!(
        grype_argv.lines().collect::<Vec<_>>(),
        vec![source.as_str(), "-o", "json"]
    );
    let cache = cache.display().to_string();
    assert!(
        trivy_env.contains(&format!("TRIVY_CACHE_DIR=\"{cache}/trivy\""))
            || trivy_env.contains(&format!("TRIVY_CACHE_DIR='{cache}/trivy'"))
            || trivy_env.contains(&format!("TRIVY_CACHE_DIR={cache}/trivy")),
        "{trivy_env}"
    );
    for wanted in [
        "GRYPE_DB_AUTO_UPDATE",
        "GRYPE_CHECK_FOR_APP_UPDATE",
        "GRYPE_DB_CACHE_DIR",
    ] {
        assert!(grype_env.contains(wanted), "{wanted} missing: {grype_env}");
    }
    assert!(
        grype_env.contains("GRYPE_DB_AUTO_UPDATE=\"false\"")
            || grype_env.contains("GRYPE_DB_AUTO_UPDATE='false'")
            || grype_env.contains("GRYPE_DB_AUTO_UPDATE=false"),
        "{grype_env}"
    );
    for env in [&trivy_env, &grype_env] {
        assert!(!env.contains(CANARY_VAR) && !env.contains(CANARY), "{env}");
        assert!(
            !env.contains("PATH=\"/") && !env.contains("PATH='/"),
            "no PATH is passed: {env}"
        );
    }

    assert_eq!(
        outcomes_only(&failed),
        vec![
            ("grype", &JobOutcome::Failed("scanner failed".to_owned())),
            ("trivy", &JobOutcome::Done)
        ]
    );
    for row in &rows {
        assert!(!row.contains(CANARY), "a secret in a row: {row}");
        // A row may name the repository (`o/app`), but never a filesystem path.
        assert!(!row.contains(&layout), "no layout path in a row: {row}");
        assert!(!row.contains(&cache), "no cache path in a row: {row}");
    }
    let logged = logs.text();
    assert!(!logged.contains(CANARY), "a secret in the logs: {logged}");
    assert!(!logged.contains(&layout), "no layout path in the logs");
}

/// A failed scanner on the newest image never posts the fixed note; once it finishes clean, the
/// note is posted and the issue stays open.
#[tokio::test]
async fn a_failed_scanner_never_notes_an_issue() {
    let (trivy, grype) = ok_scripts("");
    let fx = Fx::new("close", &trivy, &grype).await;
    fx.queue(P_OLD).await;
    fx.drain().await;
    let github = std::sync::Arc::new(FakeGithub::default());
    let gh = FakeIssues(github.clone());
    let source = {
        let mut conn = match fx.pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => panic!("conn: {err}"),
        };
        match crate::db::sources::find_by_id(&mut conn, "s1").await {
            Ok(Some(source)) => source,
            other => panic!("source: {other:?}"),
        }
    };
    let reconcile = || async {
        match crate::services::issue_lifecycle::reconcile(
            &fx.pool,
            &gh,
            b"token",
            &source,
            "ghcr.io/o/app:v2",
            NOW,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(err) => panic!("reconcile: {err:?}"),
        }
    };
    reconcile().await;
    let open = |status: &str| {
        let status = status.to_owned();
        let pool = fx.pool.clone();
        async move {
            count(
                &pool,
                "SELECT COUNT(*) FROM github_issues WHERE cve_id = 'CVE-2026-4738' AND status = ?",
                &[&status],
            )
            .await
        }
    };
    assert_eq!(open("open").await, 1, "the CRITICAL CVE has an issue");

    // A newer image. Trivy finds nothing on it; Grype fails.
    let empty = fx.dir.join("trivy-empty.json");
    if let Err(err) = std::fs::write(
        &empty,
        br#"{"SchemaVersion":2,"Trivy":{"Version":"0.76.2"},"ArtifactName":"x"}"#,
    ) {
        panic!("write: {err}");
    }
    fx.script("trivy", &format!("cat '{}'", empty.display()));
    fx.script("grype", "exit 1");
    fx.image(IMG_NEW, "sha256:new").await;
    fx.platform(P_NEW, IMG_NEW, "linux/amd64").await;
    fx.observe("v1", IMG_NEW, 200).await;
    fx.queue(P_NEW).await;
    let outcomes = fx.drain().await;
    assert_eq!(
        outcomes_only(&outcomes),
        vec![
            ("grype", &JobOutcome::Failed("scanner failed".to_owned())),
            ("trivy", &JobOutcome::Done)
        ]
    );
    reconcile().await;
    assert_eq!(
        open("open").await,
        1,
        "a failed scanner never closes an issue"
    );

    // Grype finishes clean on a retry: now every enabled scanner has a result, and none
    // reports the CVE.
    let grype_empty = fx.dir.join("grype-empty.json");
    if let Err(err) = std::fs::write(
        &grype_empty,
        br#"{"matches":[],"descriptor":{"version":"0.121.2"}}"#,
    ) {
        panic!("write: {err}");
    }
    fx.script("grype", &format!("cat '{}'", grype_empty.display()));
    exec(
        &fx.pool,
        "UPDATE jobs SET status = 'queued', next_attempt_at = 0 WHERE status = 'failed'",
        &[],
    )
    .await;
    let retried = fx.drain().await;
    assert_eq!(outcomes_only(&retried), vec![("grype", &JobOutcome::Done)]);
    assert_eq!(
        fx.runs(P_NEW)
            .await
            .iter()
            .filter(|r| r.0 == "grype")
            .count(),
        1,
        "the retry reuses its run"
    );
    reconcile().await;
    assert_eq!(open("closed").await, 0, "Dockward never closes the issue");
    assert_eq!(open("open").await, 1);
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM github_issues WHERE fixed_noted_at IS NOT NULL",
            &[]
        )
        .await,
        1,
        "the fixed note was posted"
    );
    assert_eq!(
        fx.tag_rows("v1")
            .await
            .iter()
            .find(|r| r.0 == "CVE-2026-4738")
            .map(|r| r.3.clone()),
        Some("fixed".to_owned())
    );
}

/// Each run is kept, and the latest `done` run per (platform image, scanner) is the one the
/// merged view reads. A later failed run changes nothing.
#[tokio::test]
async fn each_run_is_kept_and_the_latest_done_run_is_read() {
    let (_, grype) = ok_scripts("");
    let fx = Fx::new("history", "", &grype).await;
    exec(
        &fx.pool,
        "INSERT INTO system_config (key, value) VALUES ('scanners.enabled', 'grype')",
        &[],
    )
    .await;
    fx.queue(P_OLD).await;
    fx.drain().await;
    assert!(
        fx.merged(IMG_OLD)
            .await
            .findings
            .iter()
            .any(|f| f.package == "busybox")
    );

    // A rescan (the db_update trigger) finds nothing.
    let empty = fx.dir.join("grype-empty.json");
    if let Err(err) = std::fs::write(
        &empty,
        br#"{"matches":[],"descriptor":{"version":"0.121.2"}}"#,
    ) {
        panic!("write: {err}");
    }
    fx.script("grype", &format!("cat '{}'", empty.display()));
    let queued = queue_scans(&fx.pool, P_OLD, Some("s1"), "db_update", NOW).await;
    assert_eq!(queued.ok(), Some(1));
    // A second refresh while that rescan waits queues nothing more.
    let waiting = queue_scans(&fx.pool, P_OLD, Some("s1"), "db_update", NOW).await;
    assert_eq!(waiting.ok(), Some(0));
    fx.drain().await;
    assert!(
        fx.merged(IMG_OLD).await.findings.is_empty(),
        "the latest done run is clean"
    );
    assert!(fx.tag_rows("v1").await.iter().all(|r| r.3 == "fixed"));

    // A third run fails: the view still reads the clean run.
    fx.script("grype", "exit 1");
    let again = queue_scans(&fx.pool, P_OLD, Some("s1"), "tag_moved", NOW).await;
    assert_eq!(again.ok(), Some(1));
    fx.drain().await;
    let runs = fx.runs(P_OLD).await;
    let statuses: Vec<(&str, Option<&str>)> = runs
        .iter()
        .map(|r| (r.1.as_str(), r.2.as_deref()))
        .collect();
    // The failed attempt will retry, so its run waits in `queued` with the fixed text kept.
    assert_eq!(
        statuses,
        vec![
            ("done", None),
            ("done", None),
            ("queued", Some("scanner failed"))
        ],
        "three runs are kept: {runs:?}"
    );
    assert!(fx.merged(IMG_OLD).await.findings.is_empty());
    assert_eq!(
        count(&fx.pool, "SELECT COUNT(*) FROM scanner_findings", &[]).await,
        2,
        "the first run keeps its findings"
    );
}

/// A run whose image was evicted before it could start fails with the fixed text.
#[tokio::test]
async fn an_evicted_image_fails_the_scan_with_the_fixed_text() {
    let (trivy, grype) = ok_scripts("");
    let fx = Fx::new("evicted", &trivy, &grype).await;
    fx.queue(P_OLD).await;
    exec(
        &fx.pool,
        "UPDATE image_platforms SET state = 'evicted' WHERE id = ?",
        &[P_OLD],
    )
    .await;
    let outcomes = fx.drain().await;
    assert!(
        outcomes
            .iter()
            .all(|(_, o)| *o == JobOutcome::Permanent("image is no longer stored".to_owned()))
    );
    assert!(
        fx.runs(P_OLD)
            .await
            .iter()
            .all(|r| r.1 == "failed" && r.2.as_deref() == Some("image is no longer stored"))
    );
}

/// The publish hook reports an image ready only when none of its runs is queued or running.
#[tokio::test]
async fn the_publish_hook_waits_for_every_scan() {
    let (trivy, grype) = ok_scripts("");
    let fx = Fx::new("publish", &trivy, &grype).await;
    fx.queue(P_OLD).await;
    assert_eq!(
        publish_ready(&fx.pool, IMG_OLD, NOW).await.ok(),
        Some(false)
    );
    fx.drain().await;
    assert_eq!(publish_ready(&fx.pool, IMG_OLD, NOW).await.ok(), Some(true));
}

/// A bad payload is refused permanently and runs nothing.
#[tokio::test]
async fn a_bad_payload_is_refused() {
    let (trivy, grype) = ok_scripts("");
    let fx = Fx::new("payload", &trivy, &grype).await;
    for payload in [
        r#"{"kind":"scan"}"#,
        r#"{"kind":"scan","run_id":"../x","platform_id":"000000000000000000000000000000b1","scanner":"trivy"}"#,
        r#"{"kind":"scan","run_id":"000000000000000000000000000000c1","platform_id":"000000000000000000000000000000b1","scanner":"sh"}"#,
        r#"{"kind":"scan","run_id":"000000000000000000000000000000c1","platform_id":"000000000000000000000000000000b1","scanner":"trivy"}"#,
    ] {
        let job = ClaimedJob {
            id: "j".to_owned(),
            source_id: None,
            attempts: 0,
            payload: payload.to_owned(),
        };
        assert_eq!(
            run_scan(&fx.pool, &fx.env, &fx.store, &job, NOW).await,
            JobOutcome::Permanent("job payload is not valid".to_owned()),
            "{payload}"
        );
    }
    let _ = OsString::new();
}

/// A `MakeWriter` into a shared buffer.
#[derive(Clone, Default)]
struct LogSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl LogSink {
    fn text(&self) -> String {
        let guard = match self.0.lock() {
            Ok(guard) => guard,
            Err(poison) => poison.into_inner(),
        };
        String::from_utf8_lossy(&guard).into_owned()
    }
}

impl std::io::Write for LogSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self.0.lock() {
            Ok(mut guard) => guard.extend_from_slice(bytes),
            Err(poison) => poison.into_inner().extend_from_slice(bytes),
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogSink;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A scan's step log (#308): the step is stored with its command and outcome, its stderr is kept
/// redacted, and the report on stdout is never stored as a log line.
#[tokio::test]
async fn a_scan_step_logs_its_stderr_redacted_and_never_stores_the_report() {
    let (trivy, grype) = ok_scripts("");
    let fx = Fx::new("scan-log", &trivy, &grype).await;
    // Replace the trivy stub: it prints a credential on stderr, then cats the report on stdout.
    fx.script(
        "trivy",
        &format!(
            "echo 'pull https://robot:s3cret@registry.example.com/v2' >&2\ncat '{TRIVY_FIXTURE}'"
        ),
    );
    fx.queue(P_OLD).await;
    let outcomes = fx.drain().await;
    assert!(!outcomes.is_empty());

    let lines: Vec<String> = sqlx::query_scalar(
        "SELECT l.text FROM job_log_lines l JOIN job_log_steps s ON s.id = l.step_id
         WHERE s.command LIKE 'trivy scan%'",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap_or_default();
    assert!(
        lines.iter().all(|line| !line.contains("s3cret")),
        "a credential reached the log: {lines:?}"
    );
    // The report is the scan's stdout. None of its JSON reaches a stored line.
    assert!(
        lines.iter().all(|line| !line.contains("\"SchemaVersion\"")),
        "the report reached the log: {lines:?}"
    );
    let outcome: String = sqlx::query_scalar(
        "SELECT outcome FROM job_log_steps WHERE command LIKE 'trivy scan%' LIMIT 1",
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap_or_default();
    assert_eq!(outcome, "ok");
}

/// The payload text of the first `scan` job in the table.
async fn first_scan_payload(pool: &SqlitePool) -> String {
    sqlx::query_scalar::<_, String>(
        "SELECT payload FROM jobs WHERE json_extract(payload, '$.kind') = 'scan' ORDER BY rowid LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .unwrap_or_default()
}

#[tokio::test]
async fn a_new_scan_job_payload_carries_the_image_and_trigger() {
    let (_, grype) = ok_scripts("");
    let fx = Fx::new("payload-fields", "", &grype).await;
    fx.queue(P_OLD).await;
    let text = first_scan_payload(&fx.pool).await;
    let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    assert_eq!(value["repo_full_name"], "o/app");
    assert_eq!(value["tag"], "v1");
    assert_eq!(value["digest"], "sha256:old");
    assert_eq!(value["trigger"], "first_pull");
}

#[tokio::test]
async fn the_jobs_list_returns_the_image_of_a_new_scan_job() {
    let (_, grype) = ok_scripts("");
    let fx = Fx::new("list-image", "", &grype).await;
    fx.queue(P_OLD).await;
    let query = crate::services::jobs::ListQuery::default();
    let page = crate::services::jobs::list(&fx.pool, "u1", &query)
        .await
        .unwrap_or_else(|err| panic!("list: {err:?}"));
    let job = page
        .items
        .iter()
        .find(|job| job.kind.as_deref() == Some("scan"))
        .unwrap_or_else(|| panic!("no scan job listed"));
    assert_eq!(job.image.repo_full_name.as_deref(), Some("o/app"));
    assert_eq!(job.image.tag.as_deref(), Some("v1"));
    assert_eq!(job.image.digest.as_deref(), Some("sha256:old"));
    assert_eq!(job.trigger, "first_pull");
}

fn trivy_ghsa_report(id: &str) -> String {
    format!(
        r#"{{"SchemaVersion":2,"Trivy":{{"Version":"0.76.2"}},"Results":[{{"Vulnerabilities":[{{"VulnerabilityID":"{id}","PkgName":"glob","InstalledVersion":"10.3.0","Severity":"HIGH"}}]}}]}}"#
    )
}

const GHSA: &str = "GHSA-3g3m-2fjr-6pw4";
const GHSA_CVE: &str = "CVE-2025-64756";

fn grype_ghsa_report() -> String {
    format!(
        r#"{{"matches":[{{"vulnerability":{{"id":"{GHSA}","severity":"High"}},"artifact":{{"name":"glob","version":"10.3.0"}},"relatedVulnerabilities":[{{"id":"{GHSA}"}},{{"id":"{GHSA_CVE}"}}]}}],"descriptor":{{"version":"1.0.0"}}}}"#
    )
}

/// Trivy reports a GHSA id with no alias; the alias table already maps it to a CVE id.
#[tokio::test]
async fn trivy_ghsa_already_in_the_alias_table_resolves_to_the_cve() {
    let trivy = format!("printf '%s' '{}'", trivy_ghsa_report(GHSA));
    let fx = Fx::new("alias-resolve", &trivy, "echo '{}'").await;
    exec(
        &fx.pool,
        "INSERT INTO vulnerability_aliases (alias, primary_id) VALUES (?, ?)",
        &[GHSA, GHSA_CVE],
    )
    .await;
    assert_eq!(fx.queue(P_OLD).await, 2);
    fx.drain().await;
    let stored = count(
        &fx.pool,
        "SELECT COUNT(*) FROM scanner_findings WHERE cve_id = ? AND alias = ?",
        &[GHSA_CVE, GHSA],
    )
    .await;
    assert_eq!(stored, 1);
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM cve_findings WHERE cve_id = ? AND alias = ?",
            &[GHSA_CVE, GHSA]
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM cve_findings WHERE cve_id LIKE 'GHSA-%'",
            &[]
        )
        .await,
        0
    );
}

/// A scan that resolves a new alias records it once; a second scan does not add a row, and a
/// GHSA-only finding records nothing.
#[tokio::test]
async fn a_new_alias_is_recorded_once() {
    let grype = format!("printf '%s' '{}'", grype_ghsa_report());
    let trivy = trivy_ghsa_report("GHSA-only-0000-0000");
    let trivy = format!("printf '%s' '{trivy}'");
    let fx = Fx::new("alias-record", &trivy, &grype).await;
    assert_eq!(fx.queue(P_OLD).await, 2);
    fx.drain().await;
    let again = queue_scans(&fx.pool, P_OLD, Some("s1"), "db_update", NOW).await;
    assert_eq!(again.ok(), Some(2));
    fx.drain().await;
    let rows: Vec<(String, String)> =
        match sqlx::query_as("SELECT alias, primary_id FROM vulnerability_aliases")
            .fetch_all(&fx.pool)
            .await
        {
            Ok(rows) => rows,
            Err(err) => panic!("aliases: {err}"),
        };
    assert_eq!(rows, vec![(GHSA.to_owned(), GHSA_CVE.to_owned())]);
    // The GHSA-only finding keeps its id and has no alias.
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM scanner_findings WHERE cve_id = 'GHSA-only-0000-0000' AND alias IS NULL",
            &[]
        )
        .await,
        2
    );
}

/// `(scanner, trigger)` of every run of `P_OLD`, oldest first.
async fn run_triggers(pool: &SqlitePool) -> Vec<(String, String)> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT scanner, trigger FROM scan_runs WHERE image_platform_id = ? ORDER BY rowid",
    )
    .bind(P_OLD)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|err| panic!("runs: {err}"))
}

/// A forced scan (#335) runs again for a platform every scanner already scanned.
#[tokio::test]
async fn manual_requeues_an_already_scanned_platform() {
    let fx = Fx::new("manual-requeue", "", "").await;
    for (id, scanner) in [("r-g", "grype"), ("r-t", "trivy")] {
        exec(
            &fx.pool,
            "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
             VALUES (?, ?, ?, 'first_pull', 'done', 5)",
            &[id, P_OLD, scanner],
        )
        .await;
    }
    let queued = queue_scans(&fx.pool, P_OLD, Some("s1"), "manual", NOW).await;
    assert_eq!(queued.ok(), Some(2));
    let manual: Vec<_> = run_triggers(&fx.pool)
        .await
        .into_iter()
        .filter(|(_, trigger)| trigger == "manual")
        .collect();
    assert_eq!(manual.len(), 2);
    // Once those runs are done, another forced scan queues again.
    exec(
        &fx.pool,
        "UPDATE scan_runs SET status = 'done' WHERE trigger = 'manual'",
        &[],
    )
    .await;
    let again = queue_scans(&fx.pool, P_OLD, Some("s1"), "manual", NOW).await;
    assert_eq!(again.ok(), Some(2));
}

/// A forced scan is not queued twice while a run of the scanner waits or runs.
#[tokio::test]
async fn manual_skips_an_open_run() {
    let fx = Fx::new("manual-open", "", "").await;
    // A run with no job is failed as an orphan, so the running run has its job.
    exec(
        &fx.pool,
        "INSERT INTO jobs (id, source_id, status, payload) VALUES ('j-g', 's1', 'running', '{}')",
        &[],
    )
    .await;
    exec(
        &fx.pool,
        "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, job_id)
         VALUES ('r-g', ?, 'grype', 'first_pull', 'running', 'j-g')",
        &[P_OLD],
    )
    .await;
    let queued = queue_scans(&fx.pool, P_OLD, Some("s1"), "manual", NOW).await;
    assert_eq!(queued.ok(), Some(1), "only trivy, grype is running");
    let twice = queue_scans(&fx.pool, P_OLD, Some("s1"), "manual", NOW).await;
    assert_eq!(twice.ok(), Some(0), "both scanners have an open run now");
}

/// The normal dedup is unchanged: a first pull queues once per platform and scanner.
#[tokio::test]
async fn first_pull_dedup_unchanged() {
    let fx = Fx::new("first-pull-dedup", "", "").await;
    assert_eq!(fx.queue(P_OLD).await, 2);
    exec(&fx.pool, "UPDATE scan_runs SET status = 'done'", &[]).await;
    assert_eq!(fx.queue(P_OLD).await, 0);
    assert_eq!(
        run_triggers(&fx.pool).await,
        vec![
            ("grype".to_owned(), "first_pull".to_owned()),
            ("trivy".to_owned(), "first_pull".to_owned()),
        ]
    );
}

/// The current image of a tag is its latest observation: the newest `first_seen_at`, then the
/// newest row on a tie, as in the `newest_digest_tags` view. Its platforms come in order.
#[tokio::test]
async fn current_tag_image_uses_latest_observation() {
    let fx = Fx::new("tag-image", "", "").await;
    fx.image(IMG_NEW, "sha256:new").await;
    fx.platform(P_ARM, IMG_NEW, "linux/arm64").await;
    fx.platform(P_NEW, IMG_NEW, "linux/amd64").await;
    // `v1` moved from IMG_OLD (seen at 100) to IMG_NEW (seen at 200).
    fx.observe("v1", IMG_NEW, 200).await;
    // `v2` was seen on both at the same time: the later row wins.
    fx.observe("v2", IMG_NEW, 300).await;
    fx.observe("v2", IMG_OLD, 300).await;
    let mut conn = fx.pool.acquire().await.unwrap_or_else(|e| panic!("{e}"));
    let v1 = db::scans::current_tag_image(&mut conn, "s1", "v1")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"))
        .unwrap_or_else(|| panic!("v1 has an image"));
    assert_eq!(v1.image_id, IMG_NEW);
    assert_eq!(v1.digest, "sha256:new");
    assert_eq!(v1.repository, "o/app");
    let platforms: Vec<(&str, &str)> = v1
        .platforms
        .iter()
        .map(|p| (p.id.as_str(), p.state.as_str()))
        .collect();
    assert_eq!(platforms, vec![(P_NEW, "stored"), (P_ARM, "stored")]);
    assert_eq!(v1.platforms[0].platform_digest, format!("sha256:{P_NEW}"));
    let v2 = db::scans::current_tag_image(&mut conn, "s1", "v2")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"))
        .unwrap_or_else(|| panic!("v2 has an image"));
    assert_eq!(v2.image_id, IMG_OLD);
    // A tag never observed on the source, and another source, have no image.
    let none = db::scans::current_tag_image(&mut conn, "s1", "v9").await;
    assert!(matches!(none, Ok(None)));
    let other = db::scans::current_tag_image(&mut conn, "s2", "v1").await;
    assert!(matches!(other, Ok(None)));
}

impl Fx {
    /// The stored `scanners` text of the tag's row for the CVE (#366).
    async fn scanners_of(&self, tag: &str, cve: &str) -> Option<String> {
        match sqlx::query_scalar::<_, Option<String>>(
            "SELECT scanners FROM cve_findings
             WHERE source_id = 's1' AND image_tag = ? AND cve_id = ?",
        )
        .bind(tag)
        .bind(cve)
        .fetch_one(&self.pool)
        .await
        {
            Ok(value) => value,
            Err(err) => panic!("scanners: {err}"),
        }
    }
}

/// #366: a CVE both scanners report stores both keys, in the merged-view order.
#[tokio::test]
async fn a_cve_from_both_scanners_stores_both() {
    let (trivy, grype) = ok_scripts("");
    let fx = Fx::new("scanners-both", &trivy, &grype).await;
    fx.queue(P_OLD).await;
    fx.drain().await;
    assert_eq!(
        fx.scanners_of("v1", "CVE-2026-4738").await.as_deref(),
        Some("grype,trivy")
    );
}

/// #366: a CVE one scanner reports stores that one only.
#[tokio::test]
async fn a_cve_from_one_scanner_stores_one() {
    let (trivy, grype) = ok_scripts("");
    let fx = Fx::new("scanners-one", &trivy, &grype).await;
    fx.queue(P_OLD).await;
    fx.drain().await;
    assert_eq!(
        fx.scanners_of("v1", "CVE-2025-60876").await.as_deref(),
        Some("grype")
    );
}

/// #366: a scanner that stops reporting a CVE is removed from the tag's record on the next
/// recompute.
#[tokio::test]
async fn a_scanner_dropping_a_cve_updates_the_record() {
    let (trivy, grype) = ok_scripts("");
    let fx = Fx::new("scanners-drop", &trivy, &grype).await;
    fx.queue(P_OLD).await;
    fx.drain().await;
    let empty = fx.dir.join("grype-empty.json");
    if let Err(err) = std::fs::write(
        &empty,
        br#"{"matches":[],"descriptor":{"version":"0.121.2"}}"#,
    ) {
        panic!("write: {err}");
    }
    fx.script("grype", &format!("cat '{}'", empty.display()));
    queue_scans(&fx.pool, P_OLD, Some("s1"), "db_update", NOW)
        .await
        .ok();
    fx.drain().await;
    assert_eq!(
        fx.scanners_of("v1", "CVE-2026-4738").await.as_deref(),
        Some("trivy")
    );
}

/// #366: the record stays open while another scanner still reports the CVE; a CVE no scanner
/// reports any more is fixed.
#[tokio::test]
async fn the_record_stays_while_another_scanner_reports_it() {
    let (trivy, grype) = ok_scripts("");
    let fx = Fx::new("scanners-stay", &trivy, &grype).await;
    fx.queue(P_OLD).await;
    fx.drain().await;
    let empty = fx.dir.join("grype-empty.json");
    if let Err(err) = std::fs::write(
        &empty,
        br#"{"matches":[],"descriptor":{"version":"0.121.2"}}"#,
    ) {
        panic!("write: {err}");
    }
    fx.script("grype", &format!("cat '{}'", empty.display()));
    queue_scans(&fx.pool, P_OLD, Some("s1"), "db_update", NOW)
        .await
        .ok();
    fx.drain().await;
    let rows = fx.tag_rows("v1").await;
    let status = |cve: &str| rows.iter().find(|r| r.0 == cve).map(|r| r.3.clone());
    assert_eq!(status("CVE-2026-4738").as_deref(), Some("open"));
    assert_eq!(status("CVE-2025-60876").as_deref(), Some("fixed"));
}

const NO_CVE_REASON: &str = "no CVE id published";

/// #367: a GHSA id and a GO id with no CVE id anywhere are kept as they are, with no alias and
/// the reason the UI shows. A CVE id carries no reason.
#[tokio::test]
async fn ghsa_or_go_with_no_cve_is_kept_with_a_reason() {
    let grype = r#"{"matches":[
        {"vulnerability":{"id":"GHSA-only-0000-0000","severity":"High"},"artifact":{"name":"a","version":"1"},"relatedVulnerabilities":[{"id":"GHSA-only-0000-0000"}]},
        {"vulnerability":{"id":"GO-2024-0001","severity":"High"},"artifact":{"name":"b","version":"1"}},
        {"vulnerability":{"id":"CVE-2026-0009","severity":"High"},"artifact":{"name":"c","version":"1"}}],
        "descriptor":{"version":"1.0.0"}}"#;
    let grype = format!("printf '%s' '{grype}'");
    let fx = Fx::new("id-reason", "echo '{}'", &grype).await;
    assert_eq!(fx.queue(P_OLD).await, 2);
    fx.drain().await;
    for id in ["GHSA-only-0000-0000", "GO-2024-0001"] {
        let rows: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT alias, id_reason FROM cve_findings WHERE source_id = 's1' AND cve_id = ?",
        )
        .bind(id)
        .fetch_all(&fx.pool)
        .await
        .unwrap_or_else(|err| panic!("rows: {err}"));
        assert_eq!(rows, vec![(None, Some(NO_CVE_REASON.to_owned()))], "{id}");
    }
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM cve_findings WHERE cve_id = 'CVE-2026-0009' AND id_reason IS NULL",
            &[]
        )
        .await,
        1
    );
}

/// #367: a GHSA record stored before its CVE id was known merges into the CVE record on the
/// next scan: one row, the earlier first-seen time kept, the GHSA id as the alias, and the
/// record's GitHub issue and acceptance follow the CVE id.
#[tokio::test]
async fn an_existing_ghsa_record_merges_into_the_cve_on_rescan() {
    let grype = format!("printf '%s' '{}'", grype_ghsa_report());
    let fx = Fx::new("ghsa-merge", "echo '{}'", &grype).await;
    exec(
        &fx.pool,
        "INSERT INTO cve_findings (id, source_id, image_tag, cve_id, package, severity,
             first_seen_at, last_seen_at, status, id_reason)
         VALUES ('old', 's1', 'v1', ?, 'glob', 'HIGH', 5, 6, 'open', 'no CVE id published')",
        &[GHSA],
    )
    .await;
    exec(
        &fx.pool,
        "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by_username)
         VALUES ('acc', 's1', ?, 'r', 'u1')",
        &[GHSA],
    )
    .await;
    assert_eq!(fx.queue(P_OLD).await, 2);
    fx.drain().await;
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM cve_findings WHERE source_id = 's1' AND image_tag = 'v1'",
            &[]
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM cve_findings WHERE cve_id = ? AND alias = ? AND first_seen_at = 5
               AND id_reason IS NULL AND status = 'open'",
            &[GHSA_CVE, GHSA]
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM cve_acceptances WHERE id = 'acc' AND cve_id = ?",
            &[GHSA_CVE]
        )
        .await,
        1
    );
}

/// #379: a loopback TLS server that answers as both advisory hosts, and the lookup that asks it.
async fn advisory_fake(
    osv: &'static str,
    github: &'static str,
) -> (
    crate::services::advisory_lookup::AdvisoryLookup,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&hits);
    let (port, root) =
        crate::services::outbound::socket_tests::loopback_tls_server_with(move |head| {
            counter.fetch_add(1, Ordering::Relaxed);
            let target = head.split_whitespace().nth(1).unwrap_or("");
            let body = if target.starts_with("/v1/vulns/") {
                osv
            } else if target.starts_with("/advisories/") {
                github
            } else {
                ""
            };
            if body.is_empty() {
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_owned()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            }
        })
        .await;
    (
        crate::services::advisory_lookup::AdvisoryLookup::local(port, port, root),
        hits,
    )
}

/// #379: a GHSA id the scanner gives no CVE id for is looked up, and the record is stored under
/// the CVE id the advisory names, with the GHSA id as its alias. A second scan reads the cache.
#[tokio::test]
async fn a_ghsa_with_no_scanner_cve_is_looked_up_and_stored_under_the_cve() {
    let trivy = format!("printf '%s' '{}'", trivy_ghsa_report(GHSA));
    let mut fx = Fx::new("lookup-resolve", &trivy, "echo '{}'").await;
    let (lookup, hits) = advisory_fake(
        r#"{"id":"GHSA-3g3m-2fjr-6pw4","aliases":["CVE-2025-64756"]}"#,
        "",
    )
    .await;
    fx.env = fx.env.clone().with_advisory(lookup);
    assert_eq!(fx.queue(P_OLD).await, 2);
    fx.drain().await;
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM cve_findings WHERE cve_id = ? AND alias = ? AND id_reason IS NULL",
            &[GHSA_CVE, GHSA]
        )
        .await,
        1
    );
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    // A later scan of the same id asks nobody.
    let again = queue_scans(&fx.pool, P_OLD, Some("s1"), "db_update", NOW).await;
    assert_eq!(again.ok(), Some(2));
    fx.drain().await;
    assert_eq!(hits.load(Ordering::Relaxed), 1);
}

/// #379: an advisory with no CVE id keeps the GHSA id, with the reason, and is asked once.
#[tokio::test]
async fn a_ghsa_with_no_published_cve_keeps_its_id_and_reason() {
    let trivy = format!("printf '%s' '{}'", trivy_ghsa_report("GHSA-gpwc-27cw-rh9r"));
    let mut fx = Fx::new("lookup-none", &trivy, "echo '{}'").await;
    let (lookup, hits) = advisory_fake(r#"{"id":"GHSA-gpwc-27cw-rh9r"}"#, "").await;
    fx.env = fx.env.clone().with_advisory(lookup);
    assert_eq!(fx.queue(P_OLD).await, 2);
    fx.drain().await;
    let rows: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT alias, id_reason FROM cve_findings WHERE source_id = 's1' AND cve_id = 'GHSA-gpwc-27cw-rh9r'",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap_or_else(|err| panic!("rows: {err}"));
    assert_eq!(rows, vec![(None, Some(NO_CVE_REASON.to_owned()))]);
    assert_eq!(hits.load(Ordering::Relaxed), 1);
}

/// #379: both sources down. The scan still completes, the id stays unresolved with its reason,
/// nothing is cached, and the next scan asks again and resolves it.
#[tokio::test]
async fn both_sources_down_does_not_fail_the_scan_and_the_next_scan_retries() {
    let trivy = format!("printf '%s' '{}'", trivy_ghsa_report(GHSA));
    let mut fx = Fx::new("lookup-down", &trivy, "echo '{}'").await;
    let (down, down_hits) = advisory_fake("", "").await;
    fx.env = fx.env.clone().with_advisory(down);
    assert_eq!(fx.queue(P_OLD).await, 2);
    let outcomes = fx.drain().await;
    // The Grype stub prints no report, so only Trivy's job is the one that reads the lookup.
    assert!(
        outcomes
            .iter()
            .any(|(scanner, outcome)| scanner == "trivy" && matches!(outcome, JobOutcome::Done)),
        "{:?}",
        outcomes_only(&outcomes)
    );
    assert!(down_hits.load(Ordering::Relaxed) >= 2, "OSV, then GitHub");
    assert_eq!(
        count(&fx.pool, "SELECT COUNT(*) FROM advisory_lookups", &[]).await,
        0
    );
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM cve_findings WHERE cve_id = ? AND id_reason = ?",
            &[GHSA, NO_CVE_REASON]
        )
        .await,
        1
    );
    // The source comes back: the next scan resolves the id.
    let (up, _) = advisory_fake(r#"{"aliases":["CVE-2025-64756"]}"#, "").await;
    fx.env = fx.env.clone().with_advisory(up);
    let again = queue_scans(&fx.pool, P_OLD, Some("s1"), "db_update", NOW).await;
    assert_eq!(again.ok(), Some(2));
    fx.drain().await;
    assert_eq!(
        count(
            &fx.pool,
            "SELECT COUNT(*) FROM cve_findings WHERE cve_id = ? AND alias = ?",
            &[GHSA_CVE, GHSA]
        )
        .await,
        1
    );
}

/// #391: a tag that moves to a digest already scanned is scanned again with `tag_moved`, and
/// the scan rebuilds the tag's rows from that digest's results: a CVE it no longer reports is
/// fixed for the tag.
#[tokio::test]
async fn a_moved_tag_rescan_rebuilds_its_findings_from_the_new_digest() {
    let (_, grype) = ok_scripts("");
    let fx = Fx::new("moved-rescan", "", &grype).await;
    exec(
        &fx.pool,
        "INSERT INTO system_config (key, value) VALUES ('scanners.enabled', 'grype')",
        &[],
    )
    .await;
    // `v1` is scanned on IMG_OLD and has open rows.
    fx.queue(P_OLD).await;
    fx.drain().await;
    assert!(fx.tag_rows("v1").await.iter().any(|r| r.3 == "open"));

    // IMG_NEW was scanned earlier under another tag and is clean.
    fx.image(IMG_NEW, "sha256:new").await;
    fx.platform(P_NEW, IMG_NEW, "linux/amd64").await;
    fx.observe("v2", IMG_NEW, 150).await;
    fx.script(
        "grype",
        r#"echo '{"matches":[],"descriptor":{"version":"0.121.2"}}'"#,
    );
    fx.queue(P_NEW).await;
    fx.drain().await;
    assert!(
        fx.tag_rows("v1").await.iter().any(|r| r.3 == "open"),
        "v1 is stale"
    );

    // `v1` moves to IMG_NEW. Nothing rebuilds its rows until the rescan runs.
    fx.observe("v1", IMG_NEW, 200).await;
    let mut conn = fx.pool.acquire().await.unwrap_or_else(|e| panic!("{e}"));
    let queued = queue::queue_moved_rescan_in(&mut conn, P_NEW, "s1", NOW).await;
    assert_eq!(queued.ok(), Some(1));
    // A repeat while the rescan waits adds nothing.
    let again = queue::queue_moved_rescan_in(&mut conn, P_NEW, "s1", NOW).await;
    assert_eq!(again.ok(), Some(0));
    drop(conn);
    assert!(
        run_triggers_of(&fx.pool, P_NEW)
            .await
            .contains(&("grype".to_owned(), "tag_moved".to_owned()))
    );
    fx.drain().await;
    let rows = fx.tag_rows("v1").await;
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|r| r.3 == "fixed"), "{rows:?}");
}

async fn run_triggers_of(pool: &SqlitePool, platform: &str) -> Vec<(String, String)> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT scanner, trigger FROM scan_runs WHERE image_platform_id = ? ORDER BY rowid",
    )
    .bind(platform)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|err| panic!("runs: {err}"))
}

/// #390: a scan setup whose Trivy is a downloaded version on the volume (newer than the bundled
/// v0.76.2), with `body` as the downloaded file and `executable` its mode. The bundled scripts of
/// `fx` stay the fallback.
fn with_downloaded_trivy(
    fx: &mut Fx,
    body: &str,
    executable: bool,
) -> std::sync::Arc<crate::services::scanner::selection::ScannerPrograms> {
    use crate::services::scanner::selection::ScannerPrograms;
    use crate::services::scanner::version::Version;
    use crate::services::scanner::volume::ScannerVolume;
    let Some(downloaded) = Version::parse("0.77.0") else {
        panic!("version");
    };
    let volume = ScannerVolume::under(&fx.dir);
    let folder = volume.version_dir(Scanner::Trivy, downloaded);
    if let Err(err) = std::fs::create_dir_all(&folder) {
        panic!("dir: {err}");
    }
    let binary = volume.binary_path(Scanner::Trivy, downloaded);
    if let Err(err) = std::fs::write(&binary, format!("#!/bin/sh\n{body}\n")) {
        panic!("binary: {err}");
    }
    let mode = if executable { 0o755 } else { 0o644 };
    if let Err(err) = std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(mode)) {
        panic!("chmod: {err}");
    }
    if let Err(err) = volume.record_current(Scanner::Trivy, downloaded) {
        panic!("record: {err:?}");
    }
    let programs = std::sync::Arc::new(
        ScannerPrograms::with_bundled_paths(
            &fx.dir,
            fx.bin().join("trivy"),
            fx.bin().join("grype"),
        )
        .select_at_startup([Version::parse("0.76.2"), Version::parse("0.121.3")]),
    );
    fx.env = ScanEnv::with_selection(fx.dir.join("scanner-cache"), programs.clone());
    programs
}

#[tokio::test]
async fn a_downloaded_scanner_that_does_not_start_is_marked_broken_and_bundled_scans() {
    use crate::services::scanner::selection::Selected;
    let (trivy, grype) = ok_scripts("");
    let mut fx = Fx::new("launch-fail", &trivy, &grype).await;
    // Not executable: the spawn fails, so the binary never starts.
    let programs = with_downloaded_trivy(&mut fx, "exit 0", false);
    assert!(matches!(
        programs.state(Scanner::Trivy).selected,
        Selected::Downloaded(_)
    ));
    assert_eq!(fx.queue(P_OLD).await, 2);
    let outcomes = fx.drain().await;
    // The scan kept running: the bundled Trivy produced the report.
    assert_eq!(
        outcomes_only(&outcomes),
        vec![("grype", &JobOutcome::Done), ("trivy", &JobOutcome::Done)]
    );
    let state = programs.state(Scanner::Trivy);
    assert_eq!(state.selected, Selected::Bundled);
    assert_eq!(
        state.broken.map(|version| version.to_string()).as_deref(),
        Some("0.77.0")
    );
    assert!(fx.dir.join("scanners/trivy/0.77.0/broken").is_file());
    // Grype was never downloaded and is untouched.
    assert_eq!(programs.state(Scanner::Grype).selected, Selected::Bundled);
    assert_eq!(programs.state(Scanner::Grype).broken, None);
}

#[tokio::test]
async fn a_downloaded_scanner_that_exits_non_zero_is_a_normal_scan_failure() {
    use crate::services::scanner::selection::Selected;
    let (trivy, grype) = ok_scripts("");
    let mut fx = Fx::new("nonzero", &trivy, &grype).await;
    // It starts and exits 3: a scan failure, not a launch failure.
    let programs = with_downloaded_trivy(&mut fx, "exit 3", true);
    assert_eq!(fx.queue(P_OLD).await, 2);
    let outcomes = fx.drain().await;
    assert!(
        outcomes.iter().any(|(scanner, outcome)| scanner == "trivy"
            && matches!(outcome, JobOutcome::Failed(text) if text == "scanner failed")),
        "{:?}",
        outcomes_only(&outcomes)
    );
    let state = programs.state(Scanner::Trivy);
    assert!(matches!(state.selected, Selected::Downloaded(_)));
    assert_eq!(state.broken, None);
    assert!(!fx.dir.join("scanners/trivy/0.77.0/broken").exists());
}
