use std::time::Duration;

use std::path::Path;
use std::sync::Arc;

use axum::{
    Json, Router,
    routing::{get, post},
};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

mod api;
#[allow(dead_code)] // Crypto helpers are used by the credential and backup paths in later issues.
mod auth;
mod cli;
mod config;
#[allow(dead_code)] // Pool is consumed by handlers and workers added in later issues.
mod db;
#[allow(dead_code)] // Used by handlers and services added in later issues.
mod error;
mod models;
mod services;
mod worker;

const BIND_ADDR: &str = "0.0.0.0:8080";

/// Upper bound on the graceful drain after a stop signal. It sits inside Docker's
/// default 10-second stop timeout, so `docker stop` exits well before SIGKILL.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

async fn healthz() -> Json<Health> {
    Json(Health { status: "ok" })
}

pub(crate) fn app(trusted_proxies: Vec<config::Cidr>, state: api::state::AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/assets/{*path}", get(api::static_files::asset))
        .route("/favicon.svg", get(api::static_files::favicon))
        .route("/api/v1/auth/setup-status", get(api::auth::setup_status))
        .route("/api/v1/auth/setup", post(api::auth::setup))
        .route("/api/v1/auth/login", post(api::auth::login))
        .route("/api/v1/account/me", get(api::auth::account_me))
        .route(
            "/api/v1/account/password",
            post(api::auth::account_password),
        )
        .route("/api/v1/auth/totp/verify", post(api::totp::verify))
        .route("/api/v1/account/totp", get(api::totp::status))
        .route("/api/v1/account/totp/enrol", post(api::totp::enrol))
        .route("/api/v1/account/totp/confirm", post(api::totp::confirm))
        .route("/api/v1/account/totp/disable", post(api::totp::disable))
        .route(
            "/api/v1/admin/users/{id}/totp",
            axum::routing::delete(api::totp::admin_reset),
        )
        .route("/api/v1/auth/oidc/start", get(api::oidc::start))
        .route("/api/v1/auth/oidc/callback", get(api::oidc::callback))
        .route("/api/v1/auth/logout", post(api::auth::logout))
        .route("/api/v1/auth/logout-all", post(api::auth::logout_all))
        .route(
            "/api/v1/credentials",
            get(api::credentials::list).post(api::credentials::create),
        )
        .route(
            "/api/v1/credentials/{id}",
            axum::routing::put(api::credentials::update).delete(api::credentials::delete),
        )
        .route(
            "/api/v1/credentials/{id}/test",
            post(api::credentials::test),
        )
        .route(
            "/api/v1/image-sources/{id}/cves",
            get(api::cves::list_for_source),
        )
        .route(
            "/api/v1/image-sources/{id}/tags",
            get(api::cves::tags_for_source),
        )
        .route("/api/v1/image-sources/{id}/scan", post(api::scan::scan))
        .route(
            "/api/v1/image-sources/{id}/tags/{tag}/pull",
            post(api::tag_actions::pull),
        )
        .route(
            "/api/v1/image-sources/{id}/tags/{tag}/scan",
            post(api::tag_actions::scan),
        )
        .route("/api/v1/hubs", get(api::hubs::list).post(api::hubs::create))
        .route(
            "/api/v1/hubs/{id}",
            axum::routing::delete(api::hubs::delete),
        )
        .route(
            "/api/v1/image-sources",
            get(api::sources::list).post(api::sources::create),
        )
        .route(
            "/api/v1/image-sources/{id}",
            get(api::sources::get)
                .put(api::sources::update)
                .delete(api::sources::delete),
        )
        .route(
            "/api/v1/image-sources/{id}/credential",
            axum::routing::put(api::sources::put_credential)
                .delete(api::sources::delete_credential),
        )
        .route(
            "/api/v1/image-sources/{id}/credential/test",
            post(api::sources::test_credential),
        )
        .route(
            "/api/v1/image-sources/{id}/tag-preview",
            get(api::sources::tag_preview),
        )
        .route(
            "/api/v1/image-sources/{id}/images",
            get(api::sources::source_images),
        )
        .route("/api/v1/images", get(api::sources::all_images))
        .route(
            "/api/v1/admin/scan-settings",
            get(api::scan_settings::get).put(api::scan_settings::put),
        )
        .route("/api/v1/jobs", get(api::jobs::list))
        .route("/api/v1/jobs/failed-count", get(api::jobs::failed_count))
        .route("/api/v1/jobs/purge-failed", post(api::jobs::purge_failed))
        .route("/api/v1/jobs/{id}", get(api::jobs::get))
        .route("/api/v1/jobs/{id}/log", get(api::jobs::log))
        .route("/api/v1/jobs/{id}/retry", post(api::jobs::retry))
        .route("/api/v1/about", get(api::about::get))
        .route("/api/v1/dashboard/summary", get(api::dashboard::summary))
        .route("/api/v1/cves", get(api::cves::list))
        .route("/api/v1/cves/{id}", get(api::cves::get))
        .route("/api/v1/cves/{id}/issue", post(api::cves::issue))
        .route("/api/v1/cves/{id}/accept", post(api::cves::accept))
        .route(
            "/api/v1/cves/{id}/false-positive",
            post(api::cves::false_positive),
        )
        .route("/api/v1/cves/{id}/unaccept", post(api::cves::unaccept))
        .route("/api/v1/cves/{id}/review", post(api::cves::review))
        .route("/api/v1/admin/audit-log", get(api::admin::audit_log))
        .route("/api/v1/admin/jobs", get(api::admin::admin_jobs))
        .route("/api/v1/admin/health", get(api::admin::health))
        .route("/api/v1/admin/backup", post(api::admin::backup))
        .route("/api/v1/admin/logs", get(api::admin::logs))
        .route(
            "/api/v1/admin/log-level",
            get(api::admin::get_log_level).put(api::admin::put_log_level),
        )
        .route(
            "/api/v1/admin/alert-channels",
            get(api::admin::list_alert_channels).post(api::admin::create_alert_channel),
        )
        .route(
            "/api/v1/admin/alert-channels/{id}",
            axum::routing::put(api::admin::update_alert_channel),
        )
        .route(
            "/api/v1/admin/oidc",
            get(api::oidc::get_settings).put(api::oidc::put_settings),
        )
        .route(
            "/api/v1/admin/github-url",
            get(api::github_url::get_settings).put(api::github_url::put_settings),
        )
        .route(
            "/api/v1/admin/image-sources/{source_id}/cves/{cve_id}",
            axum::routing::delete(api::admin::delete_cve),
        )
        .route(
            "/api/v1/admin/users",
            get(api::admin::list_users).post(api::admin::create_user),
        )
        .route(
            "/api/v1/admin/users/{id}",
            axum::routing::delete(api::admin::delete_user),
        )
        .route(
            "/api/v1/admin/users/{id}/role",
            axum::routing::put(api::admin::set_role),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::csrf::guard,
        ))
        .fallback(api::static_files::spa)
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            api::hardening::TrustedProxies(std::sync::Arc::new(trusted_proxies)),
            api::hardening::resolve_client_ip,
        ))
        .layer(axum::middleware::from_fn(api::hardening::access_log))
        .layer(axum::middleware::from_fn(api::hardening::security_headers))
}

/// Resolves on the first SIGTERM or Ctrl+C.
async fn shutdown_signal(mut terminate: Signal) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let command = match cli::parse(args.get(1..).unwrap_or_default()) {
        Ok(command) => command,
        Err(usage) => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };
    // The container healthcheck runs every few seconds: it installs no logger, reads no
    // configuration and prints only a fixed line on failure (`specs/deployment.md`, Health).
    if command == cli::Command::Healthcheck {
        if cli::healthcheck(cli::HEALTHCHECK_URL).await.is_err() {
            eprintln!(
                "healthcheck failed: no 200 response from {}",
                cli::HEALTHCHECK_URL
            );
            std::process::exit(1);
        }
        return Ok(());
    }

    // Logs go to stdout and to the admin's in-memory buffer. Every start is at `info`;
    // `RUST_LOG` is ignored (`specs/security.md`, Application log). The access log
    // records route templates, so tokens in paths stay out.
    let app_log = services::app_log::install()?;

    match command {
        cli::Command::Serve => serve(app_log).await,
        cli::Command::Restore(file) => {
            if let Err(message) = run_restore(&file).await {
                eprintln!("{message}");
                std::process::exit(1);
            }
            Ok(())
        }
        cli::Command::RotateKey => {
            if let Err(message) = run_rotate_key().await {
                eprintln!("{message}");
                std::process::exit(1);
            }
            Ok(())
        }
        // Handled above, before the logger is installed.
        cli::Command::Healthcheck => Ok(()),
    }
}

/// The offline key rotation command. It never binds the HTTP port, refuses to run
/// while the app holds the port, and prints only the number of rows it rewrote.
async fn run_rotate_key() -> Result<(), String> {
    ensure_app_stopped("rotating the key")?;
    let old_key = config::load_old_encryption_key().map_err(|err| err.to_string())?;
    let new_key = config::load_encryption_key().map_err(|err| err.to_string())?;
    let settings = config::load_settings().map_err(|err| err.to_string())?;
    match rotate_database(&settings.data_dir, &old_key, &new_key).await {
        Ok(rows) => {
            println!("Re-encrypted {rows} stored values under the new key.");
            Ok(())
        }
        Err(failure) => Err(failure.message().to_owned()),
    }
}

/// Why a rotation did not run or did not finish. Each variant has a fixed message.
#[derive(Debug, PartialEq, Eq)]
enum RotateFailure {
    NoDatabase,
    SameKey,
    CouldNotOpen,
    Failed,
}

impl RotateFailure {
    fn message(&self) -> &'static str {
        match self {
            RotateFailure::NoDatabase => {
                "no database was found in DOCKWARD_DATA_DIR; nothing was changed"
            }
            RotateFailure::SameKey => {
                "DOCKWARD_OLD_ENCRYPTION_KEY and DOCKWARD_ENCRYPTION_KEY are the same key; \
                 nothing was changed"
            }
            RotateFailure::CouldNotOpen => "could not open the database; nothing was changed",
            RotateFailure::Failed => {
                "the rotation failed and the database was not changed. Check that \
                 DOCKWARD_OLD_ENCRYPTION_KEY is the key that wrote the data, and that this \
                 image version is the one the app last ran on."
            }
        }
    }
}

/// Re-encrypts the database in `data_dir` from `old_key` to `new_key`. The database is
/// opened without running migrations: a failed rotation must leave the file exactly as
/// it was, and the command must run with the image version the app last ran on.
async fn rotate_database(
    data_dir: &Path,
    old_key: &config::EncryptionKey,
    new_key: &config::EncryptionKey,
) -> Result<u64, RotateFailure> {
    let old = auth::crypto::credentials_key(old_key).map_err(|_| RotateFailure::Failed)?;
    let new = auth::crypto::credentials_key(new_key).map_err(|_| RotateFailure::Failed)?;
    if services::key_rotation::constant_time_eq(old.as_bytes(), new.as_bytes()) {
        return Err(RotateFailure::SameKey);
    }
    let path = db::database_path(data_dir);
    if !path.is_file() {
        return Err(RotateFailure::NoDatabase);
    }
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(db::connect_options(&path))
        .await
        .map_err(|_| RotateFailure::CouldNotOpen)?;
    let rotated = services::key_rotation::rotate(&pool, &old, &new).await;
    pool.close().await;
    rotated.map_err(|_| RotateFailure::Failed)
}

/// The offline restore command. It never binds the HTTP port, and it refuses to run
/// while the app holds the port.
async fn run_restore(file: &Path) -> Result<(), String> {
    ensure_app_stopped("restoring")?;
    let encryption_key = config::load_encryption_key().map_err(|err| err.to_string())?;
    let settings = config::load_settings().map_err(|err| err.to_string())?;
    restore_database(&encryption_key, &settings.data_dir, file).await?;
    println!("Restored the database from {}.", file.display());
    Ok(())
}

/// Fails when something already listens on the app port. The listener is dropped at
/// once, so the port is free again for the app.
fn ensure_app_stopped(activity: &str) -> Result<(), String> {
    match std::net::TcpListener::bind(BIND_ADDR) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(_) => Err(format!("stop Dockward before {activity}")),
    }
}

/// The backup `created_at` for the `restore.run` audit row (decided on issue #58).
/// It is the UTC timestamp in the file name `harborgate-<yyyymmddThhmmssZ>.hgbk`.
/// A file that does not match that pattern falls back to its modification time.
/// Returns `None` when neither is available.
fn backup_created_at(file: &Path) -> Option<String> {
    let from_name = file
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(timestamp_from_file_name);
    from_name.or_else(|| {
        let modified = std::fs::metadata(file)
            .and_then(|meta| meta.modified())
            .ok()?;
        let secs = modified
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        services::time::rfc3339(i64::try_from(secs).ok()?).ok()
    })
}

/// Parses `harborgate-<yyyymmddThhmmssZ>.hgbk` into an RFC 3339 string. A stamp that
/// is not a real calendar instant returns `None`.
fn timestamp_from_file_name(name: &str) -> Option<String> {
    let stamp = name.strip_prefix("harborgate-")?.strip_suffix(".hgbk")?;
    let bytes = stamp.as_bytes();
    if bytes.len() != 16 || bytes[8] != b'T' || bytes[15] != b'Z' {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = stamp.get(range)?;
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let (year, month, day) = (number(0..4)?, number(4..6)?, number(6..8)?);
    let (hour, minute, second) = (number(9..11)?, number(11..13)?, number(13..15)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    // Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let unix = days * 86_400 + hour * 3600 + minute * 60 + second;
    let text = services::time::rfc3339(unix).ok()?;
    // A day that does not exist (such as 30 February) rolls over to another date, so
    // the round trip no longer matches the stamp.
    let expected = format!(
        "{}-{}-{}T{}:{}:{}Z",
        stamp.get(0..4)?,
        stamp.get(4..6)?,
        stamp.get(6..8)?,
        stamp.get(9..11)?,
        stamp.get(11..13)?,
        stamp.get(13..15)?
    );
    (text == expected).then_some(text)
}

/// Removes the plaintext temporary database and any SQLite side files it left. A
/// missing file is not an error.
fn remove_temp_files(temp_path: &Path) {
    let _ = std::fs::remove_file(temp_path);
    for suffix in ["-wal", "-shm"] {
        let mut side = temp_path.as_os_str().to_owned();
        side.push(suffix);
        let _ = std::fs::remove_file(side);
    }
}

/// Replaces `<data_dir>/dockward.db` with the database in the backup `file`.
///
/// The live database is untouched unless the backup passes every check: the GCM tag
/// (`backup::open`), then `PRAGMA integrity_check` and the migrations on a temporary
/// copy in `data_dir`. Only then are the live `-wal` and `-shm` files removed and the
/// copy renamed over the live file (same directory, so the rename is atomic). The
/// `restore.run` audit row is appended to the restored database last. The temporary
/// copy holds the whole database in plain text and is removed on every path.
///
/// Errors are messages for the operator and name no key or file content.
async fn restore_database(
    encryption_key: &config::EncryptionKey,
    data_dir: &Path,
    file: &Path,
) -> Result<(), String> {
    let file_name = file
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "the backup path has no usable file name".to_owned())?
        .to_owned();
    let created_at = backup_created_at(file);
    let sealed = std::fs::read(file).map_err(|err| {
        format!(
            "could not read the backup file ({:?}); nothing was changed",
            err.kind()
        )
    })?;
    let backup_key = auth::crypto::backup_key(encryption_key)
        .map_err(|_| "could not derive the backup key".to_owned())?;
    let plain = services::backup::open(&backup_key, &sealed).map_err(|_| {
        "the backup file failed verification; check the file and that DOCKWARD_ENCRYPTION_KEY \
         is the key that created it. The live database was not changed."
            .to_owned()
    })?;
    drop(sealed);

    let restore_id = services::ids::new_id().map_err(|_| {
        "could not draw a random name for the restore; nothing was changed".to_owned()
    })?;
    let temp_path = data_dir.join(format!("restore-{restore_id}.tmp"));
    let staged = stage_and_swap(data_dir, &temp_path, &plain).await;
    remove_temp_files(&temp_path);
    drop(plain);
    staged?;

    // The database is replaced. Append the audit row to the restored database.
    let pool = db::open(data_dir).await.map_err(|_| {
        "the database was restored, but it could not be reopened to record the audit row".to_owned()
    })?;
    let details = serde_json::json!({ "file": file_name, "created_at": created_at });
    let recorded = record_restore(&pool, &file_name, &details).await;
    pool.close().await;
    recorded.map_err(|_| {
        "the database was restored, but the restore.run audit row could not be written".to_owned()
    })
}

/// Writes the plaintext to `temp_path`, checks it, and swaps it in for the live file.
async fn stage_and_swap(data_dir: &Path, temp_path: &Path, plain: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    // Owner-only: the file holds the whole database in plain text.
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp_path)
        .map_err(|_| "could not create the temporary file in DOCKWARD_DATA_DIR".to_owned())?;
    out.write_all(plain)
        .and_then(|()| out.sync_all())
        .map_err(|_| "could not write the temporary file in DOCKWARD_DATA_DIR".to_owned())?;
    drop(out);

    let checked = check_candidate(temp_path).await;
    checked?;

    let live = db::database_path(data_dir);
    let live_text = live.to_string_lossy().into_owned();
    for suffix in ["-wal", "-shm"] {
        let side = std::path::PathBuf::from(format!("{live_text}{suffix}"));
        match std::fs::remove_file(&side) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(
                    "could not remove the old write-ahead log; the live database was not replaced"
                        .to_owned(),
                );
            }
        }
    }
    std::fs::rename(temp_path, &live).map_err(|_| "could not replace the live database".to_owned())
}

/// Opens the candidate database, runs `PRAGMA integrity_check` (expects `ok`) and the
/// migrations, then closes it so SQLite checkpoints and removes its own log files.
async fn check_candidate(temp_path: &Path) -> Result<(), String> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(db::connect_options(temp_path))
        .await
        .map_err(|_| "the backup does not contain a usable database".to_owned())?;
    // A PRAGMA result has no column type the `query!` macro can check, so this read
    // is a plain query.
    let verdict = sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
        .fetch_one(&pool)
        .await;
    let result = match verdict {
        Ok(text) if text == "ok" => db::migrate(&pool).await.map_err(|_| {
            "the backup database could not be migrated; it may come from a newer Dockward"
                .to_owned()
        }),
        _ => Err("the backup database failed the integrity check".to_owned()),
    };
    pool.close().await;
    result
}

/// Appends the `restore.run` audit row (actor `cli`) in one transaction.
async fn record_restore(
    pool: &sqlx::SqlitePool,
    file_name: &str,
    details: &serde_json::Value,
) -> Result<(), error::AppError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| error::AppError::InternalError)?;
    services::audit::record(
        &mut tx,
        &services::audit::Actor::cli(),
        "restore.run",
        &format!("backup:{file_name}"),
        Some(details),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| error::AppError::InternalError)
}

async fn serve(app_log: Arc<services::app_log::AppLog>) -> Result<(), Box<dyn std::error::Error>> {
    // Refuse to start without a valid key or settings. This runs before the port is bound.
    let encryption_key = config::load_encryption_key()?;
    let settings = config::load_settings()?;
    config::prepare_backup_dir(&settings.backup_dir)?;
    auth::password::warm_dummy_hash().map_err(|_| "could not compute the dummy password hash")?;
    let pool = db::open(&settings.data_dir)
        .await
        .map_err(|_| "could not open or migrate the database in DOCKWARD_DATA_DIR")?;
    let session_key = Arc::new(
        auth::crypto::session_key(&encryption_key)
            .map_err(|_| "could not derive the session key")?,
    );
    let csrf_key = Arc::new(
        auth::crypto::csrf_key(&encryption_key).map_err(|_| "could not derive the CSRF key")?,
    );
    let credentials_key = Arc::new(
        auth::crypto::credentials_key(&encryption_key)
            .map_err(|_| "could not derive the credentials key")?,
    );
    let backup_key = Arc::new(
        auth::crypto::backup_key(&encryption_key).map_err(|_| "could not derive the backup key")?,
    );
    let github = services::github_url::load_target(&pool)
        .await
        .map_err(|_| "could not read the GitHub base URL settings")?;
    let discovery = Arc::new(
        services::discovery::Discovery::from_env(pool.clone(), credentials_key.clone()).map_err(
            |_| "could not build the registry client (check DOCKWARD_ALLOW_PRIVATE_REGISTRIES)",
        )?,
    );
    // A scanner version that cannot be read is null, and startup goes on. The bundled versions
    // decide whether a downloaded scanner is used, or purged (#390).
    let about = services::about::About::read_bundled(&settings.data_dir).await;
    let bundled_versions = about.bundled_versions();
    let scanner_programs = Arc::new(
        services::scanner::selection::ScannerPrograms::bundled(&settings.data_dir)
            .select_at_startup(bundled_versions),
    );
    let state = api::state::AppState {
        pool,
        session_key,
        csrf_key,
        public_url: settings.public_url.clone(),
        login_throttle: services::throttle::LoginThrottle::new(),
        login_limiter: api::hardening::RateLimiter::new(10, Duration::from_secs(60)),
        credentials_key,
        allow_private_oidc: settings.allow_private_oidc,
        allow_private_alerts: settings.allow_private_alerts,
        jwks: Arc::new(services::oidc_jwt::JwksCache::new()),
        backup_key,
        data_dir: settings.data_dir.clone(),
        backup_dir: settings.backup_dir.clone(),
        issues_client: Arc::new(
            services::github_issues::GithubIssues::new(github.clone())
                .map_err(|_| "could not build the GitHub issues client")?,
        ),
        app_log,
        github,
        discovery,
        scan_limiter: api::hardening::RateLimiter::new(1, Duration::from_secs(300)),
        registry_limiter: api::hardening::RateLimiter::new(60, std::time::Duration::from_secs(60)),
        totp_limiter: crate::api::hardening::RateLimiter::new(
            5,
            std::time::Duration::from_secs(15 * 60),
        ),
        about: Arc::new(about),
        scanner_programs,
    };
    let terminate = signal(SignalKind::terminate())?;
    let listener = TcpListener::bind(BIND_ADDR).await?;
    // Startup line: version, bind address and non-secret settings only. The encryption key,
    // tokens and secrets are never logged.
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        bind = BIND_ADDR,
        public_url = %settings.public_url,
        data_dir = %settings.data_dir.display(),
        backup_dir = %settings.backup_dir.display(),
        // Named without "private": the application log drops fields whose names hold
        // an audit secret fragment (`specs/security.md`, Application log).
        oidc_range_opt_out = settings.allow_private_oidc,
        alerts_range_opt_out = settings.allow_private_alerts,
        "Dockward starting"
    );

    // Jobs left `running` by a previous process go back to `queued` before the worker
    // starts (`specs/backend.md`, Durable job queue).
    let requeued = db::jobs::requeue_running(&state.pool, worker::now_secs())
        .await
        .map_err(|_| "could not re-queue running jobs")?;
    if requeued > 0 {
        tracing::info!(requeued, "re-queued jobs left running at startup");
    }

    // Store repair (section 4): a pull cut off by the last process is marked failed so its retry
    // can start, `.tmp` and orphan layouts are removed, and a half-done eviction is completed.
    // Counts only are logged. A failure is logged with fixed text and does not stop the start.
    let store = services::storage::StoreRoot::under(&state.data_dir);
    match services::storage::startup::repair(
        &services::storage::repository::SqlStoreRepository::new(state.pool.clone()),
        &store,
        worker::now_secs(),
    )
    .await
    {
        Ok(report) => tracing::info!(
            evictions_completed = report.evictions_completed,
            pulls_failed = report.pulls_failed,
            directories_removed = report.directories_removed,
            "image store repaired"
        ),
        Err(_) => tracing::warn!("image store repair did not finish"),
    }

    // The stop flag flips to true on the first signal. The server stops accepting
    // connections and drains in-flight requests. The instant of the signal is sent first,
    // so one 8-second budget (`drain`) covers the server and the background tasks.
    let (stop_tx, stop_rx) = watch::channel(false);
    let (stop_at_tx, mut stop_at_rx) = watch::channel(None::<Instant>);
    tokio::spawn(async move {
        shutdown_signal(terminate).await;
        let _ = stop_at_tx.send(Some(Instant::now()));
        let _ = stop_tx.send(true);
    });

    // The worker stops taking jobs on the same signal. A job it already took finishes.
    let worker_pool = state.pool.clone();
    let worker_stop = stop_rx.clone();
    // `discover` has a handler. `pull` pulls into `<data dir>/images` and queues the scans,
    // `scan` runs the scanners and the convert step, and `publish` uploads the merged SARIF and
    // runs the issue rules.
    let notifier = services::alerts::Notifier::new(
        state.pool.clone(),
        state.credentials_key.clone(),
        state.allow_private_alerts,
    );
    let publisher = services::publish::Publisher::new(
        state.pool.clone(),
        state.credentials_key.clone(),
        services::storage::StoreRoot::under(&state.data_dir),
        state.github.clone(),
    )
    .map_err(|_| "could not build the GitHub publish clients")?;
    let handler = Arc::new(services::discovery::handler::SpinoffJobs::new(
        state.discovery.clone(),
        notifier,
        state.pool.clone(),
        services::storage::StoreRoot::under(&state.data_dir),
        services::scan::ScanEnv::new(&state.data_dir, state.scanner_programs.clone()),
        publisher,
    ));
    let worker_task = tokio::spawn(async move {
        worker::run(worker_pool, handler, worker_stop).await;
    });

    // Discovery runs hourly per (hub, repository) (decision 16).
    let discovery_task = tokio::spawn(services::discovery::schedule::run(
        state.pool.clone(),
        stop_rx.clone(),
    ));

    // Retention deletes rows past their age limit, 5 minutes after start and then daily.
    let retention_task = tokio::spawn(services::retention::run(
        state.pool.clone(),
        stop_rx.clone(),
    ));

    // The scanner databases refresh every 24 hours (decision 4).
    let db_update_task = tokio::spawn(services::scanner::db_update::run(
        state.pool.clone(),
        stop_rx.clone(),
    ));

    // The latest stable Trivy and Grype releases are checked once a day (#390). The check runs on
    // its own task and never blocks a scan; a failure records nothing.
    let upstream_task = tokio::spawn(services::scanner::upstream_check::run(
        state.pool.clone(),
        services::scanner::upstream_check::UpstreamCheck::live(),
        bundled_versions,
        stop_rx.clone(),
    ));

    let mut graceful = stop_rx.clone();
    let router = app(settings.trusted_proxies.clone(), state)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
        let _ = graceful.wait_for(|stopped| *stopped).await;
    });
    let tasks = vec![
        worker_task,
        retention_task,
        discovery_task,
        db_update_task,
        upstream_task,
    ];

    let mut serve = Box::pin(std::future::IntoFuture::into_future(serve));
    let first = tokio::select! {
        result = &mut serve => Phase::Served(result),
        at = stop_instant(&mut stop_at_rx) => Phase::Stopped(at),
    };
    match first {
        Phase::Stopped(stop_at) => drain(serve, tasks, stop_at).await?,
        Phase::Served(result) => {
            // The server ended on its own, as with a listener error: exit at once.
            result?;
            let stop_at = (*stop_at_rx.borrow()).unwrap_or_else(Instant::now);
            drain(std::future::ready(Ok(())), tasks, stop_at).await?;
        }
    }
    Ok(())
}

/// What ended first: the server, or the stop signal.
enum Phase {
    Served(std::io::Result<()>),
    Stopped(Instant),
}

/// Resolves with the instant of the stop signal. A closed channel counts as now.
async fn stop_instant(stop_at: &mut watch::Receiver<Option<Instant>>) -> Instant {
    match stop_at.wait_for(|at| at.is_some()).await {
        Ok(at) => (*at).unwrap_or_else(Instant::now),
        Err(_) => Instant::now(),
    }
}

/// Drains within one `DRAIN_TIMEOUT` counted from `stop_at`, the instant of the stop
/// signal. The server and then each background task wait only until that one deadline, so
/// a stop never takes longer than the budget. A task that is still running at the deadline
/// is left to the process exit, and its job is re-queued at the next start.
async fn drain(
    serve: impl Future<Output = std::io::Result<()>>,
    tasks: Vec<JoinHandle<()>>,
    stop_at: Instant,
) -> std::io::Result<()> {
    let deadline = stop_at + DRAIN_TIMEOUT;
    let served = tokio::time::timeout_at(deadline, serve).await;
    for task in tasks {
        let _ = tokio::time::timeout_at(deadline, task).await;
    }
    served.unwrap_or(Ok(()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Real time, no clock pausing: `stop_at` lies 7 s in the past, so about 1 s of the
    /// 8 s budget remains and each drain test takes about 1 s.
    fn stop_seven_seconds_ago() -> Instant {
        Instant::now() - Duration::from_secs(7)
    }

    /// A server that never ends and a worker that sleeps 20 s: `drain` still returns at
    /// the end of the one budget, not after a second 8 s.
    #[tokio::test]
    async fn drain_never_exceeds_the_budget() {
        let worker = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(20)).await;
        });
        let started = Instant::now();
        let result = drain(
            std::future::pending::<std::io::Result<()>>(),
            vec![worker],
            stop_seven_seconds_ago(),
        )
        .await;
        let elapsed = started.elapsed();
        assert!(result.is_ok());
        assert!(
            elapsed >= Duration::from_millis(900),
            "returned before the budget ended: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(4),
            "waited past the single budget: {elapsed:?}"
        );
    }

    /// The server ends at once, so the worker gets only what remains of the budget: a
    /// worker that needs 3 s is cut off at about 1 s, and one that needs 0.3 s finishes.
    #[tokio::test]
    async fn worker_gets_only_the_remaining_budget() {
        let slow_done = Arc::new(AtomicBool::new(false));
        let slow_flag = slow_done.clone();
        let slow = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            slow_flag.store(true, Ordering::SeqCst);
        });
        let started = Instant::now();
        let result = drain(
            std::future::ready(Ok(())),
            vec![slow],
            stop_seven_seconds_ago(),
        )
        .await;
        let elapsed = started.elapsed();
        assert!(result.is_ok());
        assert!(
            elapsed < Duration::from_millis(2500),
            "the worker got more than the remaining budget: {elapsed:?}"
        );
        assert!(
            !slow_done.load(Ordering::SeqCst),
            "the slow worker should have been cut off"
        );

        let quick_done = Arc::new(AtomicBool::new(false));
        let quick_flag = quick_done.clone();
        let quick = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            quick_flag.store(true, Ordering::SeqCst);
        });
        let result = drain(
            std::future::ready(Ok(())),
            vec![quick],
            stop_seven_seconds_ago(),
        )
        .await;
        assert!(result.is_ok());
        assert!(
            quick_done.load(Ordering::SeqCst),
            "a worker inside the remaining budget must finish"
        );
    }

    /// The admin audit route rejects a request with no session cookie with 401.
    #[tokio::test]
    async fn admin_audit_log_requires_a_session() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!("dockward-app-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = db::open(&dir).await.unwrap();
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let session_key = Arc::new(auth::crypto::session_key(&root).unwrap());
        let csrf_key = Arc::new(auth::crypto::csrf_key(&root).unwrap());
        let state = api::state::AppState {
            pool: pool.clone(),
            session_key,
            csrf_key,
            public_url: "https://dockward.example.com".to_owned(),
            login_throttle: services::throttle::LoginThrottle::new(),
            login_limiter: api::hardening::RateLimiter::new(10, Duration::from_secs(60)),
            credentials_key: Arc::new(auth::crypto::credentials_key(&root).unwrap()),
            allow_private_oidc: false,
            allow_private_alerts: false,
            jwks: Arc::new(services::oidc_jwt::JwksCache::new()),
            backup_key: Arc::new(auth::crypto::backup_key(&root).unwrap()),
            data_dir: dir.clone(),
            backup_dir: dir.join("backups"),
            issues_client: std::sync::Arc::new(
                crate::services::github_issues::GithubIssues::new(Default::default()).unwrap(),
            ),
            app_log: std::sync::Arc::new(crate::services::app_log::AppLog::detached(
                crate::services::app_log::REVERT_AFTER,
            )),
            github: Default::default(),
            discovery: crate::services::discovery::Discovery::for_test(),
            scan_limiter: crate::api::hardening::RateLimiter::new(
                1,
                std::time::Duration::from_secs(300),
            ),
            registry_limiter: crate::api::hardening::RateLimiter::new(
                60,
                std::time::Duration::from_secs(60),
            ),
            totp_limiter: crate::api::hardening::RateLimiter::new(
                5,
                std::time::Duration::from_secs(15 * 60),
            ),
            about: std::sync::Arc::new(crate::services::about::About {
                dockward: env!("CARGO_PKG_VERSION").to_owned(),
                trivy: Some("v0.0.1".to_owned()),
                grype: None,
            }),
            scanner_programs: std::sync::Arc::new(
                crate::services::scanner::selection::ScannerPrograms::bundled(&dir),
            ),
        };
        let response = app(Vec::new(), state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/audit-log")
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        8080,
                    ))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A router over a fresh database, with the session and CSRF keys derived from
    /// the test key. Test values only.
    pub(crate) async fn test_router(name: &str) -> (Router, sqlx::SqlitePool, std::path::PathBuf) {
        test_router_with_throttle(name, services::throttle::LoginThrottle::new()).await
    }

    /// Like `test_router`, with the given login throttle (for example a frozen clock).
    async fn test_router_with_throttle(
        name: &str,
        login_throttle: services::throttle::LoginThrottle,
    ) -> (Router, sqlx::SqlitePool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("dockward-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = db::open(&dir).await.unwrap();
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let state = api::state::AppState {
            pool: pool.clone(),
            session_key: Arc::new(auth::crypto::session_key(&root).unwrap()),
            csrf_key: Arc::new(auth::crypto::csrf_key(&root).unwrap()),
            public_url: "https://dockward.example.com".to_owned(),
            login_throttle,
            login_limiter: api::hardening::RateLimiter::new(10, Duration::from_secs(60)),
            credentials_key: Arc::new(auth::crypto::credentials_key(&root).unwrap()),
            allow_private_oidc: false,
            allow_private_alerts: false,
            jwks: Arc::new(services::oidc_jwt::JwksCache::new()),
            backup_key: Arc::new(auth::crypto::backup_key(&root).unwrap()),
            data_dir: dir.clone(),
            backup_dir: dir.join("backups"),
            issues_client: std::sync::Arc::new(
                crate::services::github_issues::GithubIssues::new(Default::default()).unwrap(),
            ),
            app_log: std::sync::Arc::new(crate::services::app_log::AppLog::detached(
                crate::services::app_log::REVERT_AFTER,
            )),
            github: Default::default(),
            discovery: crate::services::discovery::Discovery::for_test_with_pool(pool.clone()),
            scan_limiter: crate::api::hardening::RateLimiter::new(
                1,
                std::time::Duration::from_secs(300),
            ),
            registry_limiter: crate::api::hardening::RateLimiter::new(
                60,
                std::time::Duration::from_secs(60),
            ),
            totp_limiter: crate::api::hardening::RateLimiter::new(
                5,
                std::time::Duration::from_secs(15 * 60),
            ),
            about: std::sync::Arc::new(crate::services::about::About {
                dockward: env!("CARGO_PKG_VERSION").to_owned(),
                trivy: Some("v0.76.2".to_owned()),
                grype: Some("v0.121.3".to_owned()),
            }),
            scanner_programs: std::sync::Arc::new(
                crate::services::scanner::selection::ScannerPrograms::bundled(&dir),
            ),
        };
        (app(Vec::new(), state), pool, dir)
    }

    pub(crate) fn with_peer(builder: axum::http::request::Builder) -> axum::http::request::Builder {
        builder.extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            8080,
        ))))
    }

    /// A session token signed under the pre-rename label, and a cookie under the old
    /// name, are both plain 401 responses. A token under the new key and cookie name
    /// passes the signature check (the user is then unknown, also 401, so the check
    /// below uses `verify` directly).
    #[tokio::test]
    async fn stale_session_tokens_and_old_cookie_names_are_a_plain_401() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("stale-session").await;
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let old_key = auth::crypto::derive_key(&root, b"harborgate/session-v1").unwrap();
        let now = auth::session::now_unix().unwrap();
        let stale = auth::session::issue(&old_key, "u-1", "admin", 0, now).unwrap();
        let new_key = auth::crypto::session_key(&root).unwrap();
        assert!(auth::session::verify(&new_key, &stale, now).is_err());
        let fresh = auth::session::issue(&new_key, "u-1", "admin", 0, now).unwrap();
        assert!(auth::session::verify(&new_key, &fresh, now).is_ok());
        assert!(auth::session::set_cookie(&fresh).starts_with("__Host-dockward_session="));
        assert!(auth::csrf::set_cookie("v.w").starts_with("__Host-dockward_csrf="));

        for cookie in [
            format!("__Host-dockward_session={stale}"),
            format!("__Host-harborgate_session={fresh}"),
        ] {
            let response = router
                .clone()
                .oneshot(
                    with_peer(
                        Request::builder()
                            .uri("/api/v1/admin/audit-log")
                            .header("cookie", cookie),
                    )
                    .body(Body::empty())
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A state-changing `/api` route returns `403 csrf_invalid` with no token, and with
    /// a header that does not match the cookie. A matching token passes the guard.
    #[tokio::test]
    async fn state_changing_route_needs_a_matching_csrf_token() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("csrf-route").await;
        let k = auth::crypto::csrf_key(
            &config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
        )
        .unwrap();
        let good = auth::csrf::issue(&k).unwrap();
        let cookie = format!("__Host-dockward_csrf={good}");

        let missing = with_peer(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("cookie", &cookie),
        )
        .body(Body::empty())
        .unwrap();
        let mismatch = with_peer(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("cookie", &cookie)
                .header("x-csrf-token", "other.value"),
        )
        .body(Body::empty())
        .unwrap();
        let matching = with_peer(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("cookie", &cookie)
                .header("x-csrf-token", &good),
        )
        .body(Body::empty())
        .unwrap();

        let r1 = router.clone().oneshot(missing).await.unwrap();
        let r2 = router.clone().oneshot(mismatch).await.unwrap();
        let r3 = router.oneshot(matching).await.unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(r1.status(), StatusCode::FORBIDDEN);
        assert_eq!(r2.status(), StatusCode::FORBIDDEN);
        // The matching token passes the guard. The logout handler then returns 401,
        // because no session cookie is present, so the response is not 403.
        assert_eq!(r3.status(), StatusCode::UNAUTHORIZED);
    }

    /// Posts one login from `peer`. Test values only. The password is obviously fake.
    async fn post_login(
        router: &Router,
        peer: [u8; 4],
        username: &str,
        password: &str,
    ) -> axum::http::Response<axum::body::Body> {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let body = format!(r#"{{"username":"{username}","password":"{password}"}}"#);
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("origin", "https://dockward.example.com")
            .header("content-type", "application/json")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                peer, 8080,
            ))))
            .body(Body::from(body))
            .unwrap();
        router.clone().oneshot(request).await.unwrap()
    }

    /// Five wrong passwords, then the sixth attempt is refused inside the delay with
    /// the same 401 as a wrong password. The same account from another IP still gets a
    /// password check and is not delayed. Time is frozen, so the result does not depend
    /// on scheduling.
    #[tokio::test]
    async fn failed_login_delay_is_per_account_and_client_ip() {
        use axum::http::StatusCode;

        // A frozen clock: real time never advances, so the sixth attempt is always inside
        // the 1-second wait, under any CPU load.
        let frozen = std::time::Instant::now();
        let throttle = services::throttle::LoginThrottle::with_clock(Arc::new(move || frozen));
        let (router, pool, dir) = test_router_with_throttle("login-throttle", throttle).await;
        let password = runtime_password();
        let wrong_password = runtime_password();
        services::auth::create_first_admin(&pool, "test-admin", None, &password)
            .await
            .unwrap();

        for _ in 0..5 {
            let r = post_login(&router, [192, 0, 2, 10], "test-admin", &wrong_password).await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        }
        // Inside the 1-second wait: refused without a password check, same 401 body.
        let blocked = post_login(&router, [192, 0, 2, 10], "test-admin", &password).await;
        assert_eq!(blocked.status(), StatusCode::UNAUTHORIZED);
        let blocked_body = axum::body::to_bytes(blocked.into_body(), 4096)
            .await
            .unwrap();
        let wrong = post_login(&router, [198, 51, 100, 7], "test-admin", &wrong_password).await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let wrong_body = axum::body::to_bytes(wrong.into_body(), 4096).await.unwrap();
        // Responses for a blocked attempt and a wrong password look the same.
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&blocked_body).unwrap()["error"]["code"],
            "invalid_credentials"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&wrong_body).unwrap()["error"]["code"],
            "invalid_credentials"
        );
        // Another IP is not delayed: the right password signs in.
        let other_ip = post_login(&router, [198, 51, 100, 7], "test-admin", &password).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(other_ip.status(), StatusCode::OK);
    }

    /// The eleventh login from one IP in a minute gets 429 with Retry-After.
    #[tokio::test]
    async fn login_rate_limit_is_ten_per_minute_per_ip() {
        use axum::http::StatusCode;

        let (router, pool, dir) = test_router("login-rate").await;
        let password = runtime_password();
        let wrong_password = runtime_password();
        services::auth::create_first_admin(&pool, "test-admin", None, &password)
            .await
            .unwrap();
        for n in 0..10 {
            let r = post_login(
                &router,
                [203, 0, 113, 5],
                &format!("test-nobody-{n}"),
                &wrong_password,
            )
            .await;
            assert_eq!(
                r.status(),
                StatusCode::UNAUTHORIZED,
                "attempt {n} should reach the password check"
            );
        }
        let limited = post_login(&router, [203, 0, 113, 5], "test-nobody-x", &wrong_password).await;
        let retry = limited.headers().get("retry-after").cloned();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(retry.is_some(), "429 must carry Retry-After");
    }

    /// Login and setup are exempt from the CSRF token. Without a token they must not
    /// return `csrf_invalid`, so they reach their own checks (here the same-origin
    /// check passes and the body is rejected instead). Both routes are tested.
    #[tokio::test]
    async fn login_and_setup_are_exempt_from_the_csrf_token() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("csrf-exempt").await;
        let body =
            serde_json::json!({"username": "test-x", "password": runtime_password()}).to_string();
        let login = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("origin", "https://dockward.example.com")
            .header("content-type", "application/json")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))))
            .body(Body::from(body.clone()))
            .unwrap();
        let setup = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/setup")
            .header("origin", "https://dockward.example.com")
            .header("content-type", "application/json")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))))
            .body(Body::from(body.clone()))
            .unwrap();
        let login_status = router.clone().oneshot(login).await.unwrap().status();
        let setup_status = router.oneshot(setup).await.unwrap().status();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        // The request reaches the route: login finds no user (401) and setup creates one (201).
        assert_eq!(login_status, StatusCode::UNAUTHORIZED);
        assert_eq!(setup_status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn healthz_returns_ok_json() {
        let Json(body) = healthz().await;
        assert_eq!(
            serde_json::to_string(&body).ok().as_deref(),
            Some(r#"{"status":"ok"}"#)
        );
    }

    /// A JSON request with optional cookie and CSRF header. Returns status and parsed body.
    pub(crate) async fn send_json(
        router: &Router,
        method: &str,
        uri: &str,
        cookie: Option<&str>,
        csrf: Option<&str>,
        body: &str,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        use tower::ServiceExt;
        let mut builder = with_peer(
            axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json"),
        );
        if let Some(cookie) = cookie {
            builder = builder.header("cookie", cookie);
        }
        if let Some(token) = csrf {
            builder = builder.header("x-csrf-token", token);
        }
        let request = builder
            .body(axum::body::Body::from(body.to_owned()))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// `GET /api/v1/admin/audit-log` filters by `action` and `actor_user_id`, and pages with
    /// `page` and `page_size`, through the router. Five rows: two actions, two actors.
    #[tokio::test]
    async fn audit_log_filters_and_pages_over_http() {
        use axum::http::StatusCode;
        let (router, pool, dir) = test_router("audit-http").await;
        let mut conn = pool.acquire().await.unwrap();
        db::users::insert_local(&mut conn, "adm-1", "test-admin", None, "h", "admin")
            .await
            .unwrap();
        db::users::insert_local(&mut conn, "act-2", "test-regular", None, "h", "user")
            .await
            .unwrap();
        let first = services::audit::Actor {
            user_id: Some("adm-1".to_owned()),
            username: "test-admin".to_owned(),
        };
        let second = services::audit::Actor {
            user_id: Some("act-2".to_owned()),
            username: "test-regular".to_owned(),
        };
        for (actor, action, target) in [
            (&first, "user.create", "user:a"),
            (&second, "user.create", "user:b"),
            (&first, "mapping.create", "mapping:c"),
            (&second, "mapping.create", "mapping:d"),
            (&first, "mapping.create", "mapping:e"),
        ] {
            services::audit::record(&mut conn, actor, action, target, None)
                .await
                .unwrap();
        }
        drop(conn);
        let cookie = session_cookie("adm-1", "admin", 0);

        let (status, all) = get_json(&router, "/api/v1/admin/audit-log", &cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(all["total"], 5);

        let (status, by_action) = get_json(
            &router,
            "/api/v1/admin/audit-log?action=user.create",
            &cookie,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(by_action["total"], 2);
        let actions = by_action["items"].as_array().unwrap();
        assert!(
            actions.iter().all(|item| item["action"] == "user.create"),
            "action filter let another action through"
        );

        let (status, by_actor) = get_json(
            &router,
            "/api/v1/admin/audit-log?actor_user_id=act-2",
            &cookie,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(by_actor["total"], 2);
        let actors = by_actor["items"].as_array().unwrap();
        assert!(
            actors.iter().all(|item| item["actor_user_id"] == "act-2"),
            "actor filter let another actor through"
        );

        // Paging: pages of two over five rows give 2, 2, 1, then an empty page. The
        // three pages together hold every row exactly once.
        let mut seen = Vec::new();
        for (page, expected) in [(1, 2), (2, 2), (3, 1), (4, 0)] {
            let uri = format!("/api/v1/admin/audit-log?page={page}&page_size=2");
            let (status, body) = get_json(&router, &uri, &cookie).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["page"], page);
            assert_eq!(body["page_size"], 2);
            assert_eq!(body["total"], 5);
            let items = body["items"].as_array().unwrap();
            assert_eq!(items.len(), expected, "page {page} size");
            seen.extend(items.iter().map(|item| item["id"].clone()));
        }
        let distinct: std::collections::HashSet<String> =
            seen.iter().map(|id| id.to_string()).collect();
        assert_eq!(distinct.len(), 5, "paging repeated or dropped a row");

        // Filter and paging together: three mapping rows, page two holds the last one.
        let (status, filtered) = get_json(
            &router,
            "/api/v1/admin/audit-log?action=mapping.create&page=2&page_size=2",
            &cookie,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(filtered["total"], 3);
        assert_eq!(filtered["items"].as_array().unwrap().len(), 1);

        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Login and setup refuse a cross-site request with `403 csrf_invalid`, on both routes:
    /// a foreign `Origin`, a cross-site `Sec-Fetch-Site` with no `Origin`, and neither
    /// header. The database is empty, so a request that got past the check would reach the
    /// handler and return `401` (login) or `201` (setup). A `403` shows the check refused it.
    #[tokio::test]
    async fn login_and_setup_refuse_cross_site_requests() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("cross-site").await;
        let body = format!(
            r#"{{"username":"test-x","password":"{}"}}"#,
            runtime_password()
        );
        let mut failures = Vec::new();
        for uri in ["/api/v1/auth/login", "/api/v1/auth/setup"] {
            for (label, origin, fetch_site) in [
                ("foreign origin", Some("https://evil.example.com"), None),
                (
                    "cross-site fetch metadata, no origin",
                    None,
                    Some("cross-site"),
                ),
                ("neither header", None, None),
            ] {
                let mut builder = with_peer(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header("content-type", "application/json"),
                );
                if let Some(value) = origin {
                    builder = builder.header("origin", value);
                }
                if let Some(value) = fetch_site {
                    builder = builder.header("sec-fetch-site", value);
                }
                let request = builder.body(Body::from(body.clone())).unwrap();
                let response = router.clone().oneshot(request).await.unwrap();
                let status = response.status();
                let bytes = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                failures.push((uri, label, status, json["error"]["code"].clone()));
            }
        }
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        for (uri, label, status, code) in failures {
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {label}");
            assert_eq!(code, "csrf_invalid", "{uri}: {label}");
        }
    }

    /// Two sessions of one user, each from a real login. After `POST /api/v1/account/password`
    /// with session A, session B gets `401` on `GET /api/v1/account/me`. The cookie issued by
    /// the password change response gets `200`.
    #[tokio::test]
    async fn password_change_signs_out_other_sessions_over_http() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        let (router, pool, dir) = test_router("password-http").await;
        let current = runtime_password();
        let next = runtime_password();
        services::auth::create_first_admin(&pool, "test-admin", None, &current)
            .await
            .unwrap();
        let login_a = post_login(&router, [192, 0, 2, 20], "test-admin", &current).await;
        assert_eq!(login_a.status(), StatusCode::OK);
        let login_b = post_login(&router, [192, 0, 2, 20], "test-admin", &current).await;
        assert_eq!(login_b.status(), StatusCode::OK);
        let session_a = set_cookie_value(&login_a, auth::session::SESSION_COOKIE).unwrap();
        let session_b = set_cookie_value(&login_b, auth::session::SESSION_COOKIE).unwrap();
        let csrf = set_cookie_value(&login_a, auth::csrf::CSRF_COOKIE).unwrap();
        assert_ne!(session_a, session_b, "two logins must give two sessions");

        let change = with_peer(
            Request::builder()
                .method("POST")
                .uri("/api/v1/account/password")
                .header("content-type", "application/json")
                .header(
                    "cookie",
                    format!(
                        "{}={session_a}; {}={csrf}",
                        auth::session::SESSION_COOKIE,
                        auth::csrf::CSRF_COOKIE
                    ),
                )
                .header("x-csrf-token", &csrf),
        )
        .body(Body::from(format!(
            r#"{{"current_password":"{current}","new_password":"{next}"}}"#
        )))
        .unwrap();
        let changed = router.clone().oneshot(change).await.unwrap();
        assert_eq!(changed.status(), StatusCode::NO_CONTENT);
        let session_c = set_cookie_value(&changed, auth::session::SESSION_COOKIE).unwrap();

        let (status_b, _) = get_json(
            &router,
            "/api/v1/account/me",
            &format!("{}={session_b}", auth::session::SESSION_COOKIE),
        )
        .await;
        let (status_c, _) = get_json(
            &router,
            "/api/v1/account/me",
            &format!("{}={session_c}", auth::session::SESSION_COOKIE),
        )
        .await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(status_b, StatusCode::UNAUTHORIZED, "other session survived");
        assert_eq!(status_c, StatusCode::OK, "the fresh session must work");
    }

    /// A test password drawn from the OS RNG at run time, so no password literal sits in
    /// the source. Length is well over the 15-character minimum.
    fn runtime_password() -> String {
        format!("test-pw-{}", services::ids::new_id().unwrap_or_default())
    }

    /// A signed session cookie for `user_id`, issued the way login issues one. Test key only.
    pub(crate) fn session_cookie(user_id: &str, role: &str, token_version: i64) -> String {
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let key = auth::crypto::session_key(&root).unwrap();
        let now = auth::session::now_unix().unwrap();
        let token = auth::session::issue(&key, user_id, role, token_version, now).unwrap();
        format!("{}={token}", auth::session::SESSION_COOKIE)
    }

    /// A GET with the given `cookie` header. Returns the status and the parsed JSON body.
    pub(crate) async fn get_json(
        router: &Router,
        uri: &str,
        cookie: &str,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let request = with_peer(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("cookie", cookie),
        )
        .body(Body::empty())
        .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// The value of the `Set-Cookie` named `name` on `response`, without its attributes.
    fn set_cookie_value(
        response: &axum::http::Response<axum::body::Body>,
        name: &str,
    ) -> Option<String> {
        response
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .find_map(|value| {
                let pair = value.to_str().ok()?.split(';').next()?;
                let (key, val) = pair.split_once('=')?;
                (key == name).then(|| val.to_owned())
            })
    }

    // Base64 of 32 zero bytes, and of 32 bytes of 0x01. Test values only.
    const RESTORE_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const OTHER_KEY_B64: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    /// 2001-09-09T01:46:40Z, the instant in the backup file name below.
    const BACKUP_AT: i64 = 1_000_000_000;

    fn restore_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("dockward-restore-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn add_user(pool: &sqlx::SqlitePool, username: &str) {
        let mut conn = pool.acquire().await.unwrap();
        db::users::insert_local(&mut conn, username, username, None, "test-hash", "user")
            .await
            .unwrap();
    }

    async fn usernames(data_dir: &Path) -> Vec<String> {
        let pool = db::open(data_dir).await.unwrap();
        let names: Vec<String> = sqlx::query_scalar("SELECT username FROM users ORDER BY username")
            .fetch_all(&pool)
            .await
            .unwrap();
        pool.close().await;
        names
    }

    async fn restore_audit_count(data_dir: &Path) -> i64 {
        let pool = db::open(data_dir).await.unwrap();
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'restore.run'")
                .fetch_one(&pool)
                .await
                .unwrap();
        pool.close().await;
        count
    }

    /// A live data directory holding user `live`, and a backup directory holding a
    /// backup of a database with user `backed-up`, sealed under `RESTORE_KEY_B64`.
    /// Returns (live data dir, backup file path).
    async fn live_and_backup(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let live = restore_dir(&format!("{name}-live"));
        let source = restore_dir(&format!("{name}-source"));
        let backups = restore_dir(&format!("{name}-backups"));

        let live_pool = db::open(&live).await.unwrap();
        add_user(&live_pool, "live").await;
        live_pool.close().await;

        let source_pool = db::open(&source).await.unwrap();
        add_user(&source_pool, "backed-up").await;
        let root = config::parse_encryption_key(RESTORE_KEY_B64).unwrap();
        let key = auth::crypto::backup_key(&root).unwrap();
        let file_name = services::backup::create(&source_pool, &key, &source, &backups, BACKUP_AT)
            .await
            .unwrap();
        source_pool.close().await;
        (live, backups.join(file_name))
    }

    fn stray_temp_files(data_dir: &Path) -> Vec<String> {
        std::fs::read_dir(data_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("restore-"))
            .collect()
    }

    #[tokio::test]
    async fn restore_replaces_the_database_and_appends_restore_run() {
        let (live, backup) = live_and_backup("replace").await;
        assert_eq!(usernames(&live).await, vec!["live"]);
        let root = config::parse_encryption_key(RESTORE_KEY_B64).unwrap();

        restore_database(&root, &live, &backup).await.unwrap();

        assert_eq!(usernames(&live).await, vec!["backed-up"]);
        assert!(stray_temp_files(&live).is_empty(), "temporary copy left");

        let pool = db::open(&live).await.unwrap();
        let row: (String, String, Option<String>, String) = sqlx::query_as(
            "SELECT actor_username, action, actor_user_id, details FROM audit_log
             WHERE action = 'restore.run'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        pool.close().await;
        assert_eq!(row.0, "cli");
        assert_eq!(row.1, "restore.run");
        assert_eq!(row.2, None);
        let details: serde_json::Value = serde_json::from_str(&row.3).unwrap();
        assert_eq!(
            details,
            serde_json::json!({
                "file": "harborgate-20010909T014640Z.hgbk",
                "created_at": "2001-09-09T01:46:40Z",
            })
        );
    }

    /// The decided source of `created_at`: the file name first, then the file's
    /// modification time.
    #[test]
    fn backup_created_at_prefers_the_name_then_the_modification_time() {
        assert_eq!(
            timestamp_from_file_name("harborgate-20010909T014640Z.hgbk").as_deref(),
            Some("2001-09-09T01:46:40Z")
        );
        assert_eq!(
            timestamp_from_file_name("harborgate-20010230T014640Z.hgbk"),
            None
        );
        assert_eq!(timestamp_from_file_name("renamed.hgbk"), None);

        let dir = restore_dir("created-at");
        let renamed = dir.join("renamed.hgbk");
        std::fs::write(&renamed, b"x").unwrap();
        let fallback = backup_created_at(&renamed).unwrap();
        assert!(
            fallback.ends_with('Z') && fallback.len() == 20,
            "{fallback}"
        );
        assert_eq!(backup_created_at(&dir.join("missing.hgbk")), None);
    }

    #[tokio::test]
    async fn bad_tag_leaves_the_live_database_untouched() {
        let (live, backup) = live_and_backup("bad-tag").await;
        let mut bytes = std::fs::read(&backup).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&backup, bytes).unwrap();
        let root = config::parse_encryption_key(RESTORE_KEY_B64).unwrap();

        let result = restore_database(&root, &live, &backup).await;

        assert!(result.is_err(), "a tampered backup was restored");
        assert_eq!(usernames(&live).await, vec!["live"]);
        assert_eq!(restore_audit_count(&live).await, 0);
        assert!(stray_temp_files(&live).is_empty(), "temporary copy left");
    }

    #[tokio::test]
    async fn wrong_key_leaves_the_live_database_untouched() {
        let (live, backup) = live_and_backup("wrong-key").await;
        let other = config::parse_encryption_key(OTHER_KEY_B64).unwrap();

        let result = restore_database(&other, &live, &backup).await;

        assert!(result.is_err(), "a backup restored under the wrong key");
        assert_eq!(usernames(&live).await, vec!["live"]);
        assert_eq!(restore_audit_count(&live).await, 0);
        assert!(stray_temp_files(&live).is_empty(), "temporary copy left");
    }

    #[tokio::test]
    async fn rotate_key_refuses_a_missing_database() {
        let empty = restore_dir("rotate-missing");
        let old = config::parse_encryption_key(RESTORE_KEY_B64).unwrap();
        let new = config::parse_encryption_key(OTHER_KEY_B64).unwrap();

        let result = rotate_database(&empty, &old, &new).await;

        assert_eq!(result, Err(RotateFailure::NoDatabase));
        assert!(
            !db::database_path(&empty).exists(),
            "the command created a database"
        );
    }

    /// The migrations history and the schema of the latest migration, as plain rows.
    async fn schema_state(pool: &sqlx::SqlitePool) -> (Vec<i64>, i64) {
        let versions: Vec<i64> =
            sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
                .fetch_all(pool)
                .await
                .unwrap();
        let description_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('cve_findings') WHERE name = 'description'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        (versions, description_columns)
    }

    /// A database that is behind its migrations would be changed by `db::open`. The setup
    /// removes migration 1 from the history and drops a column, so the database looks one
    /// migration behind. The rotation must leave the migrations history and the schema as they
    /// were. The expected history is every applied version except 1, so the test does not
    /// depend on how many migrations exist.
    #[tokio::test]
    async fn rotate_key_does_not_migrate_the_database() {
        let dir = restore_dir("rotate-schema");
        let pool = db::open(&dir).await.unwrap();
        let (all_versions, _) = schema_state(&pool).await;
        assert!(
            all_versions.contains(&1),
            "migration 1 is not in the history"
        );
        sqlx::query("ALTER TABLE cve_findings DROP COLUMN description")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 1")
            .execute(&pool)
            .await
            .unwrap();
        let before = schema_state(&pool).await;
        pool.close().await;
        let expected_versions: Vec<i64> = all_versions.into_iter().filter(|v| *v != 1).collect();
        assert!(
            before == (expected_versions, 0),
            "the setup did not remove migration 1"
        );

        let old = config::parse_encryption_key(RESTORE_KEY_B64).unwrap();
        let new = config::parse_encryption_key(OTHER_KEY_B64).unwrap();
        let rows = rotate_database(&dir, &old, &new).await;
        assert_eq!(rows, Ok(0), "an empty database did not rotate");

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect_with(db::connect_options(&db::database_path(&dir)))
            .await
            .unwrap();
        assert!(
            schema_state(&pool).await == before,
            "the rotation changed the migrations or the schema"
        );
        let audits: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'key.rotate'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(audits, 1, "the rotation was not audited");
        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn rotate_key_with_equal_keys_reports_same_key() {
        let dir = restore_dir("rotate-same");
        db::open(&dir).await.unwrap().close().await;
        let old = config::parse_encryption_key(RESTORE_KEY_B64).unwrap();
        let new = config::parse_encryption_key(RESTORE_KEY_B64).unwrap();

        let result = rotate_database(&dir, &old, &new).await;

        assert_eq!(result, Err(RotateFailure::SameKey));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// `POST /api/v1/cves/{id}/issue` through the router: no CSRF token is `403`, a CSRF
    /// token with no session is `401`, and another user's mapping in the percent-encoded
    /// `<mapping_id>%3A<cve_id>` form is `404`. No GitHub call is made in any case.
    #[tokio::test]
    async fn cve_issue_route_checks_csrf_session_and_tenancy() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("cve-issue-route").await;
        let mut conn = pool.acquire().await.unwrap();
        for id in ["owner-1", "other-2"] {
            db::users::insert_local(&mut conn, id, id, None, "h", "user")
                .await
                .unwrap();
        }
        drop(conn);
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('rc2', 'owner-1', 'g', 'v1:fake')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES ('rm1', 'owner-1', 'hub-default-ghcr', 'proj/app', '*', 'rc2', 'octo', 'app')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO cve_findings (id, source_id, image_tag, cve_id, severity, status)
             VALUES ('rf1', 'rm1', 'v1', 'CVE-2026-0001', 'CRITICAL', 'open')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let key = auth::crypto::csrf_key(
            &config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
        )
        .unwrap();
        let csrf = auth::csrf::issue(&key).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let other_session = session_cookie("other-2", "user", 0);
        let uri = "/api/v1/cves/rm1%3ACVE-2026-0001/issue";
        let post = |cookie: String, token: Option<&str>| {
            let mut builder = with_peer(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("cookie", cookie),
            );
            if let Some(token) = token {
                builder = builder.header("x-csrf-token", token);
            }
            builder.body(Body::empty()).unwrap()
        };

        let no_csrf = router
            .clone()
            .oneshot(post(format!("{other_session}; {csrf_cookie}"), None))
            .await
            .unwrap();
        let no_session = router
            .clone()
            .oneshot(post(csrf_cookie.clone(), Some(&csrf)))
            .await
            .unwrap();
        let foreign = router
            .clone()
            .oneshot(post(format!("{other_session}; {csrf_cookie}"), Some(&csrf)))
            .await
            .unwrap();
        // The owner's call reaches the route with the decoded id. Its stored token is not
        // real, so decryption fails before any GitHub call; what matters is that it is not 404.
        let owner_session = session_cookie("owner-1", "user", 0);
        let owner = router
            .oneshot(post(format!("{owner_session}; {csrf_cookie}"), Some(&csrf)))
            .await
            .unwrap();
        let issues: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM github_issues")
            .fetch_one(&pool)
            .await
            .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
        assert_eq!(no_session.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
        assert_ne!(owner.status(), StatusCode::NOT_FOUND);
        assert_eq!(issues, 0);
    }

    /// #129: the manual issue route for a LOW and an UNKNOWN CVE keeps every guard of the
    /// CRITICAL route. A missing `X-CSRF-Token` is `403`, no session is `401`, another user and
    /// an admin who does not own the mapping get `404`, and nothing is stored. The owner gets
    /// past routing and tenancy (the fake stored token fails before any GitHub call).
    #[tokio::test]
    async fn low_and_unknown_cve_issue_route_is_owner_only_with_csrf() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("cve-issue-route-low").await;
        let mut conn = pool.acquire().await.unwrap();
        for (id, role) in [
            ("owner-1", "user"),
            ("other-2", "user"),
            ("admin-3", "admin"),
        ] {
            db::users::insert_local(&mut conn, id, id, None, "h", role)
                .await
                .unwrap();
        }
        drop(conn);
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('rc2', 'owner-1', 'g', 'v1:fake')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES ('rm1', 'owner-1', 'hub-default-ghcr', 'proj/app', '*', 'rc2', 'octo', 'app')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO cve_findings (id, source_id, image_tag, cve_id, severity, status)
             VALUES ('rf1', 'rm1', 'v1', 'CVE-2026-0004', 'LOW', 'open'),
                    ('rf2', 'rm1', 'v1', 'CVE-2026-0005', 'UNKNOWN', 'open')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let key = auth::crypto::csrf_key(
            &config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
        )
        .unwrap();
        let csrf = auth::csrf::issue(&key).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let mut results = Vec::new();
        for cve in ["CVE-2026-0004", "CVE-2026-0005"] {
            let uri = format!("/api/v1/cves/rm1%3A{cve}/issue");
            let post = |cookie: String, token: Option<&str>| {
                let mut builder = with_peer(
                    Request::builder()
                        .method("POST")
                        .uri(&uri)
                        .header("cookie", cookie),
                );
                if let Some(token) = token {
                    builder = builder.header("x-csrf-token", token);
                }
                builder.body(Body::empty()).unwrap()
            };
            let owner_session = session_cookie("owner-1", "user", 0);
            let other_session = session_cookie("other-2", "user", 0);
            let admin_session = session_cookie("admin-3", "admin", 0);
            let status = |request: Request<Body>| {
                let router = router.clone();
                async move { router.oneshot(request).await.unwrap().status() }
            };
            results.push((
                cve,
                status(post(format!("{owner_session}; {csrf_cookie}"), None)).await,
                status(post(csrf_cookie.clone(), Some(&csrf))).await,
                status(post(format!("{other_session}; {csrf_cookie}"), Some(&csrf))).await,
                status(post(format!("{admin_session}; {csrf_cookie}"), Some(&csrf))).await,
                status(post(format!("{owner_session}; {csrf_cookie}"), Some(&csrf))).await,
            ));
        }
        let issues: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM github_issues")
            .fetch_one(&pool)
            .await
            .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        for (cve, no_csrf, no_session, foreign, admin, owner) in results {
            assert_eq!(no_csrf, StatusCode::FORBIDDEN, "{cve}");
            assert_eq!(no_session, StatusCode::UNAUTHORIZED, "{cve}");
            assert_eq!(foreign, StatusCode::NOT_FOUND, "{cve}");
            assert_eq!(
                admin,
                StatusCode::NOT_FOUND,
                "{cve}: admins cannot log issues for others"
            );
            assert_ne!(owner, StatusCode::NOT_FOUND, "{cve}");
            assert_ne!(owner, StatusCode::UNPROCESSABLE_ENTITY, "{cve}");
        }
        assert_eq!(issues, 0);
    }

    /// `POST /api/v1/cves/:id/accept`, `/false-positive` and `/unaccept` through the full
    /// router: a missing `X-CSRF-Token` is `403`, a CSRF token with no session is `401`, and
    /// another user's mapping in the percent-encoded `<mapping_id>%3A<cve_id>` form is `404`
    /// with nothing stored. The owner gets `201` and then `204`; a false positive while an
    /// acceptance is active is `409`, and after the un-accept it is `201`.
    #[tokio::test]
    async fn cve_accept_routes_check_csrf_session_and_tenancy() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("cve-accept-route").await;
        let mut conn = pool.acquire().await.unwrap();
        for id in ["owner-1", "other-2"] {
            db::users::insert_local(&mut conn, id, id, None, "h", "user")
                .await
                .unwrap();
        }
        drop(conn);
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('rc2', 'owner-1', 'g', 'v1:fake')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES ('rm1', 'owner-1', 'hub-default-ghcr', 'proj/app', '*', 'rc2', 'octo', 'app')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO cve_findings (id, source_id, image_tag, cve_id, severity, status)
             VALUES ('rf1', 'rm1', 'v1', 'CVE-2026-0001', 'CRITICAL', 'open')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let key = auth::crypto::csrf_key(
            &config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
        )
        .unwrap();
        let csrf = auth::csrf::issue(&key).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let other = format!("{}; {csrf_cookie}", session_cookie("other-2", "user", 0));
        let owner = format!("{}; {csrf_cookie}", session_cookie("owner-1", "user", 0));
        let post = |action: &str, cookie: &str, token: Option<&str>| {
            let mut builder = with_peer(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/cves/rm1%3ACVE-2026-0001/{action}"))
                    .header("cookie", cookie)
                    .header("content-type", "application/json"),
            );
            if let Some(token) = token {
                builder = builder.header("x-csrf-token", token);
            }
            let body = if action == "accept" || action == "false-positive" {
                Body::from(r#"{"reason":"vendor fix scheduled","expires_at":null}"#)
            } else {
                Body::empty()
            };
            builder.body(body).unwrap()
        };

        let mut statuses = Vec::new();
        for (action, cookie, token) in [
            ("accept", other.as_str(), None),
            ("false-positive", other.as_str(), None),
            ("unaccept", other.as_str(), None),
            ("accept", csrf_cookie.as_str(), Some(csrf.as_str())),
            ("false-positive", csrf_cookie.as_str(), Some(csrf.as_str())),
            ("unaccept", csrf_cookie.as_str(), Some(csrf.as_str())),
            ("accept", other.as_str(), Some(csrf.as_str())),
            ("false-positive", other.as_str(), Some(csrf.as_str())),
            ("unaccept", other.as_str(), Some(csrf.as_str())),
        ] {
            let response = router
                .clone()
                .oneshot(post(action, cookie, token))
                .await
                .unwrap();
            statuses.push(response.status());
        }
        let stored_before_owner: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cve_acceptances")
            .fetch_one(&pool)
            .await
            .unwrap();
        let owner_accept = router
            .clone()
            .oneshot(post("accept", &owner, Some(&csrf)))
            .await
            .unwrap()
            .status();
        let foreign_unaccept_after = router
            .clone()
            .oneshot(post("unaccept", &other, Some(&csrf)))
            .await
            .unwrap()
            .status();
        let fp_while_accepted = router
            .clone()
            .oneshot(post("false-positive", &owner, Some(&csrf)))
            .await
            .unwrap()
            .status();
        let owner_unaccept = router
            .clone()
            .oneshot(post("unaccept", &owner, Some(&csrf)))
            .await
            .unwrap()
            .status();
        let owner_fp = router
            .clone()
            .oneshot(post("false-positive", &owner, Some(&csrf)))
            .await
            .unwrap()
            .status();
        let kinds: Vec<String> =
            sqlx::query_scalar("SELECT kind FROM cve_acceptances WHERE revoked_at IS NULL")
                .fetch_all(&pool)
                .await
                .unwrap();
        let fp_audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'cve.false_positive'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let owner_unaccept_fp = router
            .oneshot(post("unaccept", &owner, Some(&csrf)))
            .await
            .unwrap()
            .status();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            statuses,
            [
                StatusCode::FORBIDDEN,
                StatusCode::FORBIDDEN,
                StatusCode::FORBIDDEN,
                StatusCode::UNAUTHORIZED,
                StatusCode::UNAUTHORIZED,
                StatusCode::UNAUTHORIZED,
                StatusCode::NOT_FOUND,
                StatusCode::NOT_FOUND,
                StatusCode::NOT_FOUND,
            ]
        );
        assert_eq!(stored_before_owner, 0);
        assert_eq!(owner_accept, StatusCode::CREATED);
        assert_eq!(foreign_unaccept_after, StatusCode::NOT_FOUND);
        assert_eq!(owner_unaccept, StatusCode::NO_CONTENT);
        assert_eq!(fp_while_accepted, StatusCode::CONFLICT);
        assert_eq!(owner_fp, StatusCode::CREATED);
        assert_eq!(kinds, ["false_positive"]);
        assert_eq!(fp_audits, 1);
        assert_eq!(owner_unaccept_fp, StatusCode::NO_CONTENT);
    }

    /// The CVE read routes through the full router: no session is `401` on all three, another
    /// user's mapping is `404` (also in the percent-encoded `<mapping_id>%3A<cve_id>` form, and
    /// as the `mapping_id` filter), and the owner gets `200` with no CSRF token, because a GET
    /// needs none. `scope=all` from a user is `403`; an admin may read the owner's CVEs.
    #[tokio::test]
    async fn cve_read_routes_check_session_and_tenancy() {
        let (router, pool, dir) = test_router("cve-read-routes").await;
        let mut conn = pool.acquire().await.unwrap();
        for (id, role) in [
            ("owner-1", "user"),
            ("other-2", "user"),
            ("admin-3", "admin"),
        ] {
            db::users::insert_local(&mut conn, id, id, None, "h", role)
                .await
                .unwrap();
        }
        drop(conn);
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('rc2', 'owner-1', 'g', 'v1:fake')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES ('rm1', 'owner-1', 'hub-default-ghcr', 'proj/app', '*', 'rc2', 'octo', 'app')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO cve_findings (id, source_id, image_tag, cve_id, severity, status)
             VALUES ('rf1', 'rm1', 'v1', 'CVE-2026-0001', 'CRITICAL', 'open'),
                    ('rf2', 'rm1', 'v2', 'CVE-2026-0001', 'HIGH', 'open'),
                    ('rf3', 'rm1', 'v3', 'CVE-2026-0001', 'LOW', 'fixed')",
        )
        .execute(&pool)
        .await
        .unwrap();
        for sql in [
            "INSERT INTO images (id, hub_id, repository, digest, is_index)
             VALUES ('ri1', 'hub-default-ghcr', 'proj/app', 'sha256:00', 0)",
            "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state)
             VALUES ('rp1', 'ri1', 'linux/amd64', 'sha256:00', 'stored')",
            "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
             VALUES ('rs1', 'rp1', 'grype', 'first_pull', 'done', 1000)",
            "INSERT INTO tag_observations (source_id, tag, image_id, first_seen_at, last_seen_at)
             VALUES ('rm1', 'v1', 'ri1', 1000, 1000), ('rm1', 'v2', 'ri1', 1000, 1000),
                    ('rm1', 'v3', 'ri1', 1000, 1000)",
        ] {
            sqlx::query(sql).execute(&pool).await.unwrap();
        }

        let owner = session_cookie("owner-1", "user", 0);
        let other = session_cookie("other-2", "user", 0);
        let admin = session_cookie("admin-3", "admin", 0);
        let mapping_list = "/api/v1/image-sources/rm1/cves";
        let all_list = "/api/v1/cves";
        let filtered = "/api/v1/cves?source_id=rm1";
        let detail = "/api/v1/cves/rm1%3ACVE-2026-0001";

        let mut statuses = Vec::new();
        for (uri, cookie) in [
            (mapping_list, ""),
            (all_list, ""),
            (detail, ""),
            (mapping_list, other.as_str()),
            (filtered, other.as_str()),
            (detail, other.as_str()),
            (
                "/api/v1/image-sources/rm1/cves?page_size=201",
                other.as_str(),
            ),
            ("/api/v1/cves?scope=all", other.as_str()),
            (
                "/api/v1/image-sources/rm1/cves?page_size=201",
                owner.as_str(),
            ),
        ] {
            statuses.push(get_json(&router, uri, cookie).await.0);
        }
        let (owner_list, owner_page) = get_json(&router, mapping_list, &owner).await;
        let (owner_all, owner_all_page) = get_json(&router, all_list, &owner).await;
        let (other_all, other_page) = get_json(&router, all_list, &other).await;
        let (owner_detail, owner_body) = get_json(&router, detail, &owner).await;
        let (admin_detail, _) = get_json(&router, detail, &admin).await;
        let (admin_all, admin_page) = get_json(&router, "/api/v1/cves?scope=all", &admin).await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        use axum::http::StatusCode;
        assert_eq!(
            statuses,
            [
                StatusCode::UNAUTHORIZED,
                StatusCode::UNAUTHORIZED,
                StatusCode::UNAUTHORIZED,
                StatusCode::NOT_FOUND,
                StatusCode::NOT_FOUND,
                StatusCode::NOT_FOUND,
                StatusCode::NOT_FOUND,
                StatusCode::FORBIDDEN,
                StatusCode::BAD_REQUEST,
            ]
        );
        assert_eq!(owner_list, StatusCode::OK);
        assert_eq!(
            owner_page["total"], 1,
            "one CVE on three tags is one summary"
        );
        assert_eq!(owner_page["items"][0]["id"], "rm1:CVE-2026-0001");
        assert_eq!(owner_page["items"][0]["severity"], "CRITICAL");
        assert_eq!(owner_page["items"][0]["open_tags"], 2);
        assert_eq!(
            (owner_all, owner_all_page["total"].clone()),
            (StatusCode::OK, 1.into())
        );
        assert_eq!(
            (other_all, other_page["total"].clone()),
            (StatusCode::OK, 0.into())
        );
        assert_eq!(owner_detail, StatusCode::OK);
        assert_eq!(owner_body["cve_id"], "CVE-2026-0001");
        assert_eq!(owner_body["tags"].as_array().map(Vec::len), Some(3));
        assert!(owner_body["acceptance"].is_null());
        assert_eq!(admin_detail, StatusCode::OK);
        assert_eq!(
            (admin_all, admin_page["total"].clone()),
            (StatusCode::OK, 1.into())
        );
    }

    /// The read routes of this issue through the full router. A `GET` with no session is
    /// `401`. A `GET` is not CSRF-guarded, so a missing token does not turn it into `403`.
    /// A regular user gets `403` for `scope=all` and `404` for another tenant's job, and the
    /// owner's own job is `200`. The admin jobs route is `401`, then `403`, then `200`.
    #[tokio::test]
    async fn read_routes_check_session_tenancy_and_scope() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("read-routes").await;
        let mut conn = pool.acquire().await.unwrap();
        for id in ["owner-1", "other-2", "admin-3"] {
            let role = if id == "admin-3" { "admin" } else { "user" };
            db::users::insert_local(&mut conn, id, id, None, "h", role)
                .await
                .unwrap();
        }
        drop(conn);
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('rc2', 'owner-1', 'g', 'v1:fake')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES ('rm1', 'owner-1', 'hub-default-ghcr', 'proj/app', '*', 'rc2', 'octo', 'app')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO jobs (id, source_id, status, attempts, payload, created_at, updated_at)
             VALUES ('job-owner', 'rm1', 'failed', 8, '{}', 1000, 2000)",
        )
        .execute(&pool)
        .await
        .unwrap();
        db::job_runs::insert(
            &pool,
            &db::job_runs::JobRun {
                id: "run-1".to_owned(),
                job_kind: "discover".to_owned(),
                started_at: 1_000,
                finished_at: None,
                status: "failed".to_owned(),
                processed_count: 0,
                error_summary: Some("x".repeat(2_000)),
                scanner: None,
            },
        )
        .await
        .unwrap();

        let owner = session_cookie("owner-1", "user", 0);
        let other = session_cookie("other-2", "user", 0);
        let admin = session_cookie("admin-3", "admin", 0);
        let get = |uri: &str, cookie: Option<&str>| {
            let mut builder = with_peer(Request::builder().method("GET").uri(uri));
            if let Some(cookie) = cookie {
                builder = builder.header("cookie", cookie);
            }
            builder.body(Body::empty()).unwrap()
        };

        // Anonymous requests are 401 on every new route.
        for uri in [
            "/api/v1/jobs",
            "/api/v1/jobs/job-owner",
            "/api/v1/dashboard/summary",
            "/api/v1/admin/jobs",
        ] {
            let response = router.clone().oneshot(get(uri, None)).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }

        // Tenancy: the owner reads the job, another user gets 404 with no oracle.
        let (owner_status, _) = get_json(&router, "/api/v1/jobs/job-owner", &owner).await;
        let (other_status, other_body) = get_json(&router, "/api/v1/jobs/job-owner", &other).await;
        let (missing_status, missing_body) =
            get_json(&router, "/api/v1/jobs/no-such-job", &other).await;
        assert_eq!(owner_status, StatusCode::OK);
        assert_eq!(other_status, StatusCode::NOT_FOUND);
        assert_eq!(missing_status, StatusCode::NOT_FOUND);
        assert_eq!(
            other_body, missing_body,
            "a foreign job must look like a missing one"
        );

        // A foreign source_id filter is an empty page, not 404.
        let (foreign_status, foreign_page) =
            get_json(&router, "/api/v1/jobs?source_id=rm1", &other).await;
        assert_eq!(foreign_status, StatusCode::OK);
        assert_eq!(foreign_page["total"], 0);

        // scope=all is admin only.
        let (user_all, _) = get_json(&router, "/api/v1/jobs?scope=all", &other).await;
        let (admin_all, admin_page) = get_json(&router, "/api/v1/jobs?scope=all", &admin).await;
        assert_eq!(user_all, StatusCode::FORBIDDEN);
        assert_eq!(admin_all, StatusCode::OK);
        assert_eq!(admin_page["total"], 1);
        let (user_summary_all, _) =
            get_json(&router, "/api/v1/dashboard/summary?scope=all", &other).await;
        assert_eq!(user_summary_all, StatusCode::FORBIDDEN);

        // The admin jobs route: a regular user is 403, an admin is 200 and the error text is capped.
        let (user_jobs, _) = get_json(&router, "/api/v1/admin/jobs", &owner).await;
        let (admin_jobs, admin_jobs_body) = get_json(&router, "/api/v1/admin/jobs", &admin).await;
        assert_eq!(user_jobs, StatusCode::FORBIDDEN);
        assert_eq!(admin_jobs, StatusCode::OK);
        let capped = admin_jobs_body["items"][0]["error_summary"]
            .as_str()
            .unwrap()
            .chars()
            .count();
        assert_eq!(capped, 500);

        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The CSRF guard applies to every state-changing route. The retry route is `POST`, so
    /// a missing `X-CSRF-Token` is `403 csrf_invalid` before the handler runs, and the
    /// failed job stays failed. With a matching token and the owner's session it is `200`.
    #[tokio::test]
    async fn job_retry_checks_csrf_session_and_tenancy() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("retry-route").await;
        let mut conn = pool.acquire().await.unwrap();
        for id in ["owner-1", "other-2"] {
            db::users::insert_local(&mut conn, id, id, None, "h", "user")
                .await
                .unwrap();
        }
        drop(conn);
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('rc2', 'owner-1', 'g', 'v1:fake')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES ('rm1', 'owner-1', 'hub-default-ghcr', 'proj/app', '*', 'rc2', 'octo', 'app')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO jobs (id, source_id, status, attempts, payload, created_at, updated_at)
             VALUES ('job-1', 'rm1', 'failed', 8, '{}', 1000, 2000)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let key = auth::crypto::csrf_key(
            &config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
        )
        .unwrap();
        let csrf = auth::csrf::issue(&key).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let owner = format!("{}; {csrf_cookie}", session_cookie("owner-1", "user", 0));
        let other = format!("{}; {csrf_cookie}", session_cookie("other-2", "user", 0));
        let post = |cookie: &str, token: Option<&str>| {
            let mut builder = with_peer(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/jobs/job-1/retry")
                    .header("cookie", cookie),
            );
            if let Some(token) = token {
                builder = builder.header("x-csrf-token", token);
            }
            builder.body(Body::empty()).unwrap()
        };

        let no_csrf = router.clone().oneshot(post(&owner, None)).await.unwrap();
        let foreign = router
            .clone()
            .oneshot(post(&other, Some(&csrf)))
            .await
            .unwrap();
        let still_failed: String = sqlx::query_scalar("SELECT status FROM jobs WHERE id = 'job-1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        let owner_retry = router.oneshot(post(&owner, Some(&csrf))).await.unwrap();
        let owner_status = owner_retry.status();
        let retry_body = axum::body::to_bytes(owner_retry.into_body(), 64 * 1024)
            .await
            .unwrap();
        let retried: serde_json::Value = serde_json::from_slice(&retry_body).unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
        assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
        assert_eq!(still_failed, "failed");
        assert_eq!(owner_status, StatusCode::OK);
        assert_eq!(retried["status"], "queued");
        assert!(retried["created_at"].as_str().unwrap().ends_with('Z'));
    }

    /// The manual scan route: no session is `401`, a POST without a CSRF token is `403`, another
    /// user's source is `404` (the same as a missing one), the owner's scan queues discovery and
    /// returns `{"queued": n}`, an admin may scan any source, and a second scan of the same
    /// source inside 5 minutes is `429` with `Retry-After` (another source is not limited).
    #[tokio::test]
    async fn manual_scan_route_checks_session_tenancy_and_the_rate_limit() {
        use crate::services::discovery::tests as fake;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("scan-route").await;
        let script = Arc::new(fake::Script::default());
        let authority = fake::serve(script.clone()).await;
        fake::set_tags(&script, "team/app", &["1.0"]);
        fake::put_single(&script, "team/app", "1.0", "amd64", "route");
        let mut conn = pool.acquire().await.unwrap();
        for (id, role) in [
            ("owner-1", "user"),
            ("other-2", "user"),
            ("admin-3", "admin"),
        ] {
            db::users::insert_local(&mut conn, id, id, None, "h", role)
                .await
                .unwrap();
        }
        drop(conn);
        sqlx::query("INSERT INTO hubs (id, host, kind) VALUES ('hub-fake', ?, 'custom')")
            .bind(&authority)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('rc2', 'owner-1', 'g', 'v1:fake')",
        )
        .execute(&pool)
        .await
        .unwrap();
        for id in ["rm1", "rm2"] {
            sqlx::query(
                "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
                 VALUES (?, 'owner-1', 'hub-fake', 'team/app', ?, 'rc2', 'octo', 'app')",
            )
            .bind(id)
            .bind(if id == "rm1" { "1.*" } else { "latest" })
            .execute(&pool)
            .await
            .unwrap();
        }

        let key = auth::crypto::csrf_key(
            &config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
        )
        .unwrap();
        let csrf = auth::csrf::issue(&key).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let cookie_for =
            |user: &str, role: &str| format!("{}; {csrf_cookie}", session_cookie(user, role, 0));
        let post = |uri: &str, cookie: Option<&str>, token: bool| {
            let mut builder = with_peer(Request::builder().method("POST").uri(uri));
            if let Some(cookie) = cookie {
                builder = builder.header("cookie", cookie);
            }
            if token {
                builder = builder.header("x-csrf-token", csrf.as_str());
            }
            builder.body(Body::empty()).unwrap()
        };
        let owner = cookie_for("owner-1", "user");
        let other = cookie_for("other-2", "user");
        let admin = cookie_for("admin-3", "admin");
        let uri = "/api/v1/image-sources/rm1/scan";

        let anonymous = router
            .clone()
            .oneshot(post(uri, Some(&csrf_cookie), true))
            .await
            .unwrap();
        let no_csrf = router
            .clone()
            .oneshot(post(uri, Some(&owner), false))
            .await
            .unwrap();
        let foreign = router
            .clone()
            .oneshot(post(uri, Some(&other), true))
            .await
            .unwrap();
        let missing = router
            .clone()
            .oneshot(post("/api/v1/image-sources/nope/scan", Some(&owner), true))
            .await
            .unwrap();
        let first = router
            .clone()
            .oneshot(post(uri, Some(&owner), true))
            .await
            .unwrap();
        let first_status = first.status();
        let first_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(first.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let limited = router
            .clone()
            .oneshot(post(uri, Some(&owner), true))
            .await
            .unwrap();
        let limited_status = limited.status();
        let retry_after = limited
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        // The admin may scan another user's source, and that source has its own budget.
        let admin_scan = router
            .clone()
            .oneshot(post("/api/v1/image-sources/rm2/scan", Some(&admin), true))
            .await
            .unwrap();
        let admin_status = admin_scan.status();
        let admin_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(admin_scan.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let pulls: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM jobs WHERE json_extract(payload, '$.kind') = 'pull'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let audited: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'source.scan'")
                .fetch_one(&pool)
                .await
                .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
        assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(first_body["queued"], 1);
        assert_eq!(limited_status, StatusCode::TOO_MANY_REQUESTS);
        assert!(retry_after.is_some_and(|secs| (1..=300).contains(&secs)));
        assert_eq!(admin_status, StatusCode::OK);
        // `latest` is not in the tag list, so the admin's source queues nothing.
        assert_eq!(admin_body["queued"], 0);
        assert_eq!(pulls, 1);
        assert_eq!(audited, 2);
    }

    /// The purge routes: no session is `401`, a POST without a CSRF token is `403`
    /// `csrf_invalid` and deletes nothing, `scope=all` is admin only (`403` for a user),
    /// another scope is `400`, and the owner's purge returns `{"deleted"}` and a count of 0.
    #[tokio::test]
    async fn job_purge_routes_check_csrf_session_and_scope() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("purge-route").await;
        let mut conn = pool.acquire().await.unwrap();
        for id in ["owner-1", "other-2"] {
            db::users::insert_local(&mut conn, id, id, None, "h", "user")
                .await
                .unwrap();
        }
        db::users::insert_local(&mut conn, "admin-1", "admin-1", None, "h", "admin")
            .await
            .unwrap();
        drop(conn);
        sqlx::query(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('pc2', 'owner-1', 'g', 'v1:fake')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO image_sources (id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES ('pm1', 'owner-1', 'hub-default-ghcr', 'proj/app', '*', 'pc2', 'octo', 'app')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO jobs (id, source_id, status, attempts, payload, created_at, updated_at)
             VALUES ('pj-1', 'pm1', 'failed', 8, '{}', 1000, 2000),
                    ('pj-2', 'pm1', 'queued', 0, '{}', 1000, 2000)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let key = auth::crypto::csrf_key(
            &config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
        )
        .unwrap();
        let csrf = auth::csrf::issue(&key).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let owner = format!("{}; {csrf_cookie}", session_cookie("owner-1", "user", 0));
        let other = format!("{}; {csrf_cookie}", session_cookie("other-2", "user", 0));
        let admin = format!("{}; {csrf_cookie}", session_cookie("admin-1", "admin", 0));
        let request = |method: &str, uri: &str, cookie: Option<&str>, token: Option<&str>| {
            let mut builder = with_peer(Request::builder().method(method).uri(uri));
            if let Some(cookie) = cookie {
                builder = builder.header("cookie", cookie);
            }
            if let Some(token) = token {
                builder = builder.header("x-csrf-token", token);
            }
            builder.body(Body::empty()).unwrap()
        };
        let purge = "/api/v1/jobs/purge-failed";
        let count = "/api/v1/jobs/failed-count";
        let body_of = |response: axum::response::Response| async move {
            let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        };

        let no_session = router
            .clone()
            .oneshot(request("GET", count, None, None))
            .await
            .unwrap();
        let no_csrf = router
            .clone()
            .oneshot(request("POST", purge, Some(&owner), None))
            .await
            .unwrap();
        let user_all = router
            .clone()
            .oneshot(request(
                "POST",
                "/api/v1/jobs/purge-failed?scope=all",
                Some(&other),
                Some(&csrf),
            ))
            .await
            .unwrap();
        let bad_scope = router
            .clone()
            .oneshot(request(
                "GET",
                "/api/v1/jobs/failed-count?scope=mine",
                Some(&owner),
                None,
            ))
            .await
            .unwrap();
        let admin_own = router
            .clone()
            .oneshot(request("GET", count, Some(&admin), None))
            .await
            .unwrap();
        let admin_own = body_of(admin_own).await;
        let admin_all = router
            .clone()
            .oneshot(request(
                "GET",
                "/api/v1/jobs/failed-count?scope=all",
                Some(&admin),
                None,
            ))
            .await
            .unwrap();
        let admin_all = body_of(admin_all).await;
        let owner_count = router
            .clone()
            .oneshot(request("GET", count, Some(&owner), None))
            .await
            .unwrap();
        let owner_count = body_of(owner_count).await;
        let other_purge = router
            .clone()
            .oneshot(request("POST", purge, Some(&other), Some(&csrf)))
            .await
            .unwrap();
        let other_purge = body_of(other_purge).await;
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        let owner_purge = router
            .clone()
            .oneshot(request("POST", purge, Some(&owner), Some(&csrf)))
            .await
            .unwrap();
        let owner_status = owner_purge.status();
        let owner_purge = body_of(owner_purge).await;
        let after: Vec<String> = sqlx::query_scalar("SELECT id FROM jobs")
            .fetch_all(&pool)
            .await
            .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(no_session.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
        assert_eq!(user_all.status(), StatusCode::FORBIDDEN);
        assert_eq!(bad_scope.status(), StatusCode::BAD_REQUEST);
        assert_eq!(admin_own["count"], 0);
        assert_eq!(admin_all["count"], 1);
        assert_eq!(owner_count["count"], 1);
        assert_eq!(other_purge["deleted"], 0);
        assert_eq!(
            remaining, 2,
            "a non-owner purge and a CSRF-less POST delete nothing"
        );
        assert_eq!(owner_status, StatusCode::OK);
        assert_eq!(owner_purge["deleted"], 1);
        assert_eq!(after, ["pj-2"]);
    }

    /// The application log routes: no session is `401`, a regular user is `403` on
    /// both routes, a PUT without a CSRF token is `403 csrf_invalid`, an invalid level
    /// is `422` with fixed text that does not echo the value, and an admin change is
    /// `200` and audited as `log.level_change` with `{"old","new"}` only.
    #[tokio::test]
    async fn admin_log_routes_check_role_csrf_and_level() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let (router, pool, dir) = test_router("app-log-routes").await;
        let mut conn = pool.acquire().await.unwrap();
        db::users::insert_local(&mut conn, "admin-1", "admin-1", None, "h", "admin")
            .await
            .unwrap();
        db::users::insert_local(&mut conn, "user-1", "user-1", None, "h", "user")
            .await
            .unwrap();
        drop(conn);
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let csrf = auth::csrf::issue(&auth::crypto::csrf_key(&root).unwrap()).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let admin = format!("{}; {csrf_cookie}", session_cookie("admin-1", "admin", 0));
        let user = format!("{}; {csrf_cookie}", session_cookie("user-1", "user", 0));
        let put = |cookie: &str, token: Option<&str>, body: &str| {
            let mut builder = with_peer(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/admin/log-level")
                    .header("content-type", "application/json")
                    .header("cookie", cookie),
            );
            if let Some(token) = token {
                builder = builder.header("x-csrf-token", token);
            }
            builder.body(Body::from(body.to_owned())).unwrap()
        };
        let debug = r#"{"level":"debug"}"#;

        let (anon_logs, _) = get_json(&router, "/api/v1/admin/logs", &csrf_cookie).await;
        let (user_logs, _) = get_json(&router, "/api/v1/admin/logs", &user).await;
        let (user_level, _) = get_json(&router, "/api/v1/admin/log-level", &user).await;
        let anon_put = router
            .clone()
            .oneshot(put(&csrf_cookie, Some(&csrf), debug))
            .await
            .unwrap()
            .status();
        let user_put = router
            .clone()
            .oneshot(put(&user, Some(&csrf), debug))
            .await
            .unwrap()
            .status();
        let no_csrf = router
            .clone()
            .oneshot(put(&admin, None, debug))
            .await
            .unwrap();
        let no_csrf_status = no_csrf.status();
        let no_csrf_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(no_csrf.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let invalid = router
            .clone()
            .oneshot(put(&admin, Some(&csrf), r#"{"level":"verbose-xyz"}"#))
            .await
            .unwrap();
        let invalid_status = invalid.status();
        let invalid_text = String::from_utf8(
            axum::body::to_bytes(invalid.into_body(), 64 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let ok = router
            .clone()
            .oneshot(put(&admin, Some(&csrf), debug))
            .await
            .unwrap();
        let ok_status = ok.status();
        let ok_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(ok.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let (level_status, level_body) = get_json(&router, "/api/v1/admin/log-level", &admin).await;
        let (logs_status, logs_body) =
            get_json(&router, "/api/v1/admin/logs?level=warn&q=x", &admin).await;
        let (bad_filter, _) = get_json(&router, "/api/v1/admin/logs?level=loud", &admin).await;
        let audit: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
            "SELECT action, actor_username, target, details FROM audit_log ORDER BY rowid",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(anon_logs, StatusCode::UNAUTHORIZED);
        assert_eq!(anon_put, StatusCode::UNAUTHORIZED);
        assert_eq!(user_logs, StatusCode::FORBIDDEN);
        assert_eq!(user_level, StatusCode::FORBIDDEN);
        assert_eq!(user_put, StatusCode::FORBIDDEN);
        assert_eq!(no_csrf_status, StatusCode::FORBIDDEN);
        assert_eq!(no_csrf_body["error"]["code"], "csrf_invalid");
        assert_eq!(invalid_status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(invalid_text.contains("level must be info, debug, or trace."));
        assert!(
            !invalid_text.contains("verbose-xyz"),
            "the value was echoed"
        );
        assert_eq!(ok_status, StatusCode::OK);
        assert_eq!(ok_body["level"], "debug");
        assert!(ok_body["reverts_at"].as_str().unwrap().ends_with('Z'));
        assert_eq!(level_status, StatusCode::OK);
        assert_eq!(level_body["level"], "debug");
        assert_eq!(logs_status, StatusCode::OK);
        assert!(logs_body["items"].is_array());
        assert_eq!(logs_body["level"], "debug");
        assert_eq!(bad_filter, StatusCode::BAD_REQUEST);
        // Only the admin's change is audited; refused requests write nothing.
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].0, "log.level_change");
        assert_eq!(audit[0].1, "admin-1");
        assert_eq!(audit[0].2, "log_level");
        let details: serde_json::Value =
            serde_json::from_str(audit[0].3.as_deref().unwrap()).unwrap();
        assert_eq!(details, serde_json::json!({"old": "info", "new": "debug"}));
    }
    /// A `MakeWriter` into a shared buffer, to read what the log layer wrote.
    #[derive(Clone, Default)]
    pub(crate) struct LogSink(pub(crate) std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogSink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The admin GitHub URL routes (#184). Covers: (1) an empty value stores the default and
    /// reads back as `""`; (2) an https URL with a path `/api/v3` is accepted and used as the
    /// prefix of a repository call; (3) every invalid shape is `422 validation_failed` with
    /// `settings.github_url_invalid`; (4) a non-admin gets `403` and an anonymous caller `401`;
    /// (5) a token-like sentinel in the request is absent from every error body and log line;
    /// (6) a path in `web_url` is `422`.
    #[tokio::test]
    async fn admin_github_url_routes() {
        use axum::http::StatusCode;
        let (router, pool, dir) = test_router("github-url-routes").await;
        let mut conn = pool.acquire().await.unwrap();
        for (id, role) in [("ga", "admin"), ("gu", "user")] {
            db::users::insert_local(&mut conn, id, id, None, "h", role)
                .await
                .unwrap();
        }
        drop(conn);
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let csrf = auth::csrf::issue(&auth::crypto::csrf_key(&root).unwrap()).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let admin = format!("{}; {csrf_cookie}", session_cookie("ga", "admin", 0));
        let user = format!("{}; {csrf_cookie}", session_cookie("gu", "user", 0));
        let uri = "/api/v1/admin/github-url";
        const TOKEN: &str = "ghp_SENTINEL-github-token-9c1d";

        let sink = LogSink::default();
        let writer = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        // (4) access control.
        let (anon, _) = get_json(&router, uri, &csrf_cookie).await;
        let (forbidden_get, _) = get_json(&router, uri, &user).await;
        let (forbidden_put, _) = send_json(
            &router,
            "PUT",
            uri,
            Some(&user),
            Some(&csrf),
            r#"{"api_base_url":"","web_url":""}"#,
        )
        .await;
        assert_eq!(anon, StatusCode::UNAUTHORIZED);
        assert_eq!(forbidden_get, StatusCode::FORBIDDEN);
        assert_eq!(forbidden_put, StatusCode::FORBIDDEN);

        // (1) empty means the default.
        let (status, body) = get_json(&router, uri, &admin).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"api_base_url": "", "web_url": ""}));
        let (status, body) = send_json(
            &router,
            "PUT",
            uri,
            Some(&admin),
            Some(&csrf),
            r#"{"api_base_url":"","web_url":""}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"api_base_url": "", "web_url": ""}));

        // (3) and (6) invalid values are 422 with the fixed message and are not stored.
        let invalid_api = [
            "http://ghes.example.com/api/v3",
            "https://user:pw@ghes.example.com/api/v3",
            "https://ghes.example.com:8443/api/v3",
            "https://ghes.example.com/api/v3?x=1",
            "https://ghes.example.com/api/v3#f",
            "https://ghes.example.com/api/../v3",
            "https://ghes.example.com/api//v3",
            "https://ghes.example.com/api%2Fv3",
            "https://ghes.example.com/api%2fv3",
        ];
        for bad in invalid_api {
            let payload = serde_json::json!({"api_base_url": bad, "web_url": ""}).to_string();
            let (status, body) =
                send_json(&router, "PUT", uri, Some(&admin), Some(&csrf), &payload).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
            assert_eq!(body["error"]["code"], "validation_failed", "{bad}");
            assert_eq!(
                body["error"]["message"], "settings.github_url_invalid",
                "{bad}"
            );
        }
        // (6) a path in web_url.
        let payload =
            serde_json::json!({"api_base_url": "", "web_url": "https://ghes.example.com/x"})
                .to_string();
        let (status, body) =
            send_json(&router, "PUT", uri, Some(&admin), Some(&csrf), &payload).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"]["message"], "settings.github_url_invalid");
        // (5) a token in userinfo is refused and never echoed or logged.
        let payload = serde_json::json!({
            "api_base_url": format!("https://{TOKEN}@ghes.example.com/api/v3"),
            "web_url": ""
        })
        .to_string();
        let (status, body) =
            send_json(&router, "PUT", uri, Some(&admin), Some(&csrf), &payload).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!body.to_string().contains(TOKEN), "{body}");
        let (_, unchanged) = get_json(&router, uri, &admin).await;
        assert_eq!(
            unchanged,
            serde_json::json!({"api_base_url": "", "web_url": ""})
        );

        // (2) a path is accepted, stored, and read back.
        let payload = serde_json::json!({
            "api_base_url": "https://ghes.example.com/api/v3",
            "web_url": "https://ghes.example.com"
        })
        .to_string();
        let (status, body) =
            send_json(&router, "PUT", uri, Some(&admin), Some(&csrf), &payload).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            serde_json::json!({
                "api_base_url": "https://ghes.example.com/api/v3",
                "web_url": "https://ghes.example.com"
            })
        );
        let (_, read) = get_json(&router, uri, &admin).await;
        assert_eq!(read, body);

        // The router is a clone of the one that holds the target, so the request path of a
        // repository call under the saved base is the prefix plus the REST path.
        let stored = services::github_url::load_stored(&pool).await.unwrap();
        let urls =
            services::github_url::GithubUrls::from_stored(&stored.api_base_url, &stored.web_url)
                .unwrap();
        let call = urls
            .api_url(&services::credential_probe::github_repo_path("octo", "app"))
            .unwrap();
        assert_eq!(call.host_str(), Some("ghes.example.com"));
        assert_eq!(call.path(), "/api/v3/repos/octo/app");

        // Clearing returns to the default.
        let (status, _) = send_json(
            &router,
            "PUT",
            uri,
            Some(&admin),
            Some(&csrf),
            r#"{"api_base_url":"","web_url":""}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let audit: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action LIKE 'github%'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            audit, 0,
            "no audit row is written for the GitHub URL change"
        );

        let logged = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(
            !logged.contains(TOKEN),
            "the token reached the log: {logged}"
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
