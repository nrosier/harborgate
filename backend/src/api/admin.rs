//! Admin routes. Every handler takes `AdminUser`, so a non-admin gets `403` and a
//! missing or invalid session gets `401`.

use std::fmt;
use std::net::IpAddr;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::api::auth::AdminUser;
use crate::api::hardening::{ClientIp, ClientIpSource};
use crate::api::state::AppState;
use crate::auth::session;
use crate::db::credentials as credential_rows;
use crate::db::credentials::CredentialRow;
use crate::db::sources as source_rows;
use crate::error::AppError;
use crate::models::role::Role;
use crate::models::user::User;
use crate::services::alert_channels::{self, Channel, ListQuery};
use crate::services::app_log;
use crate::services::audit::{self, AuditEntry, AuditQuery};
use crate::services::backup as backup_service;
use crate::services::credential_probe::{self, GithubProbe, OutboundGithubProbe};
use crate::services::credentials;
use crate::services::health::{self, GithubAnswers, HealthReport};
use crate::services::job_runs::{self as job_runs, JobRunItem, ListQuery as JobRunsListQuery};
use crate::services::pagination::Page;
use crate::services::users as user_service;

/// Raw query values for `GET /api/v1/admin/audit-log`.
#[derive(Debug, Deserialize)]
pub struct AuditLogParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub action: Option<String>,
    pub actor_user_id: Option<String>,
}

/// `GET /api/v1/admin/audit-log`. Paginated, with `action` and `actor_user_id` filters.
pub async fn audit_log(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(params): Query<AuditLogParams>,
) -> Result<Json<Page<AuditEntry>>, AppError> {
    let query = AuditQuery {
        page: params.page,
        page_size: params.page_size,
        sort: params.sort,
        order: params.order,
        action: params.action,
        actor_user_id: params.actor_user_id,
    };
    Ok(Json(audit::list(&state.pool, &query).await?))
}

/// Raw query values for `GET /api/v1/admin/jobs`.
#[derive(Debug, Deserialize)]
pub struct AdminJobsParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub kind: Option<String>,
}

/// `GET /api/v1/admin/jobs`. Housekeeping runs (cleanup, retention, polling), newest first,
/// paginated, with an optional `kind` filter.
pub async fn admin_jobs(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(params): Query<AdminJobsParams>,
) -> Result<Json<Page<JobRunItem>>, AppError> {
    let query = JobRunsListQuery {
        page: params.page,
        page_size: params.page_size,
        sort: params.sort,
        order: params.order,
        kind: params.kind,
    };
    Ok(Json(job_runs::list(&state.pool, &query).await?))
}

/// Body for `POST /api/v1/admin/users`. Local accounts only.
#[derive(Deserialize)]
pub struct CreateUserBody {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
    pub role: String,
}

const REDACTED: &str = "<redacted>";

impl fmt::Debug for CreateUserBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateUserBody")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &REDACTED)
            .field("role", &self.role)
            .finish()
    }
}

/// Body for `PUT /api/v1/admin/users/:id/role`.
#[derive(Debug, Deserialize)]
pub struct RoleBody {
    pub role: String,
}

/// Parses a JSON body into `T`. A malformed body becomes `400 invalid_request`.
fn parse_body<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|_| AppError::InvalidRequest("The request body is not valid.".to_owned()))
}

/// `GET /api/v1/admin/users`. Every user, oldest first.
pub async fn list_users(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<User>>, AppError> {
    let rows = user_service::list(&state.pool).await?;
    let users = rows
        .into_iter()
        .map(User::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(users))
}

/// `POST /api/v1/admin/users`. Creates a local user. Returns `201`.
pub async fn create_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let body: CreateUserBody = parse_body(&body)?;
    let role = user_service::parse_role(&body.role)?;
    let actor = audit::Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    let id = user_service::create_local(
        &state.pool,
        &actor,
        &body.username,
        body.email.as_deref(),
        &body.password,
        role,
    )
    .await?;
    let row = crate::db::users::find_by_id(&state.pool, &id)
        .await?
        .ok_or(AppError::InternalError)?;
    Ok((StatusCode::CREATED, Json(User::try_from(row)?)).into_response())
}

/// Body for `POST /api/v1/admin/alert-channels`. `config` holds secrets, so `Debug`
/// does not print it.
#[derive(Deserialize)]
pub struct CreateChannelBody {
    pub kind: String,
    #[serde(default)]
    pub enabled: bool,
    pub config: serde_json::Value,
}

impl fmt::Debug for CreateChannelBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateChannelBody")
            .field("kind", &self.kind)
            .field("enabled", &self.enabled)
            .field("config", &REDACTED)
            .finish()
    }
}

/// Body for `PUT /api/v1/admin/alert-channels/:id`. Without `config` only `enabled`
/// changes. `config` is write-only.
#[derive(Deserialize)]
pub struct UpdateChannelBody {
    pub enabled: Option<bool>,
    pub config: Option<serde_json::Value>,
}

impl fmt::Debug for UpdateChannelBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateChannelBody")
            .field("enabled", &self.enabled)
            .field("config", &self.config.as_ref().map(|_| REDACTED))
            .finish()
    }
}

/// Raw query values for `GET /api/v1/admin/alert-channels`.
#[derive(Debug, Deserialize)]
pub struct ChannelListParams {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
}

/// `GET /api/v1/admin/alert-channels`. Paginated. The config is never returned.
pub async fn list_alert_channels(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(params): Query<ChannelListParams>,
) -> Result<Json<Page<Channel>>, AppError> {
    let query = ListQuery {
        page: params.page,
        page_size: params.page_size,
        sort: params.sort,
        order: params.order,
    };
    Ok(Json(alert_channels::list(&state.pool, &query).await?))
}

/// `POST /api/v1/admin/alert-channels`. Returns `201`, or `422` for an invalid config.
pub async fn create_alert_channel(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let body: CreateChannelBody = parse_body(&body)?;
    let actor = audit::Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    let channel = alert_channels::create(
        &state.pool,
        &state.credentials_key,
        &actor,
        state.allow_private_alerts,
        &body.kind,
        body.enabled,
        body.config,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(channel)).into_response())
}

/// `PUT /api/v1/admin/alert-channels/:id`. Returns `200`, `404`, or `422`.
pub async fn update_alert_channel(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<Channel>, AppError> {
    let body: UpdateChannelBody = parse_body(&body)?;
    let actor = audit::Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    let channel = alert_channels::update(
        &state.pool,
        &state.credentials_key,
        &actor,
        state.allow_private_alerts,
        &id,
        body.enabled,
        body.config,
    )
    .await?;
    Ok(Json(channel))
}

/// `POST /api/v1/admin/backup`. Writes an encrypted backup to `DOCKWARD_BACKUP_DIR`
/// and audits `backup.run` after the file exists. Returns `201` with the file name
/// and the directory. A missing or unwritable directory is `500 internal_error`.
pub async fn backup(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
) -> Result<Response, AppError> {
    let now = crate::auth::session::now_unix()?;
    let file = backup_service::create(
        &state.pool,
        &state.backup_key,
        &state.data_dir,
        &state.backup_dir,
        now,
    )
    .await?;
    let actor = audit::Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    backup_service::record_run(&state.pool, &actor, &file).await?;
    let path = state
        .backup_dir
        .to_str()
        .ok_or(AppError::InternalError)?
        .to_owned();
    let body = serde_json::json!({"file": file, "path": path});
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// `DELETE /api/v1/admin/users/:id`. Returns `204`, or `409` for the self and last-admin cases.
pub async fn delete_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let actor = audit::Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    user_service::delete_user(&state.pool, &actor, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/v1/admin/image-sources/:source_id/cves/:cve_id`. Deletes one CVE record of one
/// source (#349). Returns `204`; `404` for a record the source does not hold; `409` while the
/// record has an active acceptance.
pub async fn delete_cve(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    path: Result<Path<(String, String)>, axum::extract::rejection::PathRejection>,
) -> Result<StatusCode, AppError> {
    let Path((source_id, cve_id)) = path.map_err(|_| AppError::NotFound)?;
    let actor = audit::Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    crate::services::cves::delete_record(
        &state.pool,
        &actor,
        &source_id,
        &cve_id,
        crate::worker::now_secs(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /api/v1/admin/users/:id/role`. Returns the updated `User`.
pub async fn set_role(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<User>, AppError> {
    let body: RoleBody = parse_body(&body)?;
    let role: Role = user_service::parse_role(&body.role)?;
    let actor = audit::Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    user_service::change_role(&state.pool, &actor, &id, role).await?;
    let row = crate::db::users::find_by_id(&state.pool, &id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(User::try_from(row)?))
}

/// Raw query values for `GET /api/v1/admin/logs`.
#[derive(Debug, Deserialize)]
pub struct LogsParams {
    pub level: Option<String>,
    pub q: Option<String>,
}

/// `GET /api/v1/admin/logs`. The recent application log, oldest first, with an optional
/// minimum level and text search. Never mixed with the audit log.
pub async fn logs(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(params): Query<LogsParams>,
) -> Result<Json<app_log::LogsView>, AppError> {
    Ok(Json(
        app_log::read(&state.app_log, params.level.as_deref(), params.q.as_deref()).await?,
    ))
}

/// `GET /api/v1/admin/log-level`. The current level and when it reverts to `info`.
pub async fn get_log_level(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<app_log::LevelStatus>, AppError> {
    Ok(Json(state.app_log.level.status().await?))
}

/// Body for `PUT /api/v1/admin/log-level`.
#[derive(Debug, Deserialize)]
pub struct LogLevelBody {
    pub level: String,
}

/// `PUT /api/v1/admin/log-level`. Sets the global level and audits `log.level_change`.
/// An invalid level is `422` with fixed text.
pub async fn put_log_level(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    body: axum::body::Bytes,
) -> Result<Json<app_log::LevelStatus>, AppError> {
    let body: LogLevelBody = parse_body(&body)?;
    let level = app_log::parse_level(&body.level)?;
    let actor = audit::Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    Ok(Json(
        state.app_log.level.set(&state.pool, &actor, level).await?,
    ))
}

/// The `request` block of the health response: the caller's client IP and where it came
/// from (`specs/api.md`, Health). It shows only the caller's own address.
#[derive(Debug, Serialize)]
pub struct RequestInfo {
    pub client_ip: String,
    pub source: &'static str,
}

/// `GET /api/v1/admin/health` body: the report plus the caller's `request` block.
#[derive(Serialize)]
pub struct HealthBody {
    #[serde(flatten)]
    pub report: HealthReport,
    pub request: RequestInfo,
}

/// `GET /api/v1/admin/health`. Admin only. Runs the probes one after another.
/// Nothing is cached on the server.
pub async fn health(
    State(state): State<AppState>,
    _admin: AdminUser,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Extension(source): Extension<ClientIpSource>,
) -> Result<Json<HealthBody>, AppError> {
    let github = OutboundGithubProbe::new(state.github.clone())?;
    Ok(Json(health_body(&state, &github, client_ip, source).await?))
}

/// Builds the health body from the given probes. Generic over the probes, so tests pass
/// fakes and make no network call.
pub async fn health_body<G: GithubProbe>(
    state: &AppState,
    github: &G,
    client_ip: IpAddr,
    source: ClientIpSource,
) -> Result<HealthBody, AppError> {
    let now = session::now_unix()?;
    let report = report(state, github, now).await?;
    Ok(HealthBody {
        report,
        request: RequestInfo {
            client_ip: client_ip.to_string(),
            source: source.as_str(),
        },
    })
}

/// Runs the GitHub checks. GitHub gets one check per source target, probed with that
/// source's GitHub credential. Probes run one after another.
pub async fn report<G: GithubProbe>(
    state: &AppState,
    github: &G,
    _now: i64,
) -> Result<HealthReport, AppError> {
    let targets = source_rows::all_targets(&state.pool).await?;
    let mut github_checks = Vec::with_capacity(targets.len());
    for target in &targets {
        let cred = load_github_credential(state, target).await?;
        let token = credentials::decrypt_token(&state.credentials_key, &cred)?;
        let owner = target.github_owner.as_str();
        let repo = target.github_repo.as_str();
        let answers = GithubAnswers {
            repo: github
                .get(&credential_probe::github_repo_path(owner, repo), &token)
                .await,
            code_scanning: github
                .get(
                    &credential_probe::github_code_scanning_path(owner, repo),
                    &token,
                )
                .await,
            issues: github
                .get(&credential_probe::github_issues_path(owner, repo), &token)
                .await,
        };
        github_checks.push(health::github_health(
            &cred.id,
            &cred.label,
            owner,
            repo,
            answers,
        )?);
    }

    Ok(HealthReport {
        github: github_checks,
    })
}

/// Loads the GitHub credential a source target uses. The credential always belongs to
/// the source's owner, so the owner-scoped lookup is the right one.
async fn load_github_credential(
    state: &AppState,
    target: &source_rows::TargetRow,
) -> Result<CredentialRow, AppError> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|_| AppError::InternalError)?;
    credential_rows::find_owned(&mut conn, &target.user_id, &target.github_cred_id)
        .await?
        .ok_or(AppError::InternalError)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Fakes and seeding for the health tests. No socket is opened: the probes answer
    //! from fixed values, and the database is a fresh local file per test.

    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use sqlx::SqlitePool;

    use crate::api::hardening::RateLimiter;
    use crate::api::state::AppState;
    use crate::auth::crypto::{self, DerivedKey};
    use crate::config;
    use crate::db::credentials::{self as credential_rows, CredentialRow};
    use crate::error::AppError;
    use crate::services::credential_probe::{GithubProbe, GithubResponse};

    /// A fake GitHub token, for the check that the health body never holds a token.
    pub const FAKE_GITHUB_TOKEN: &str = "test-github-token-value";

    /// GitHub fake with the recorded answers: repository `200`, code scanning `404`
    /// "no analysis found", issues `403`. It records every path it was asked for.
    #[derive(Default)]
    pub struct FixedGithub {
        pub calls: Mutex<Vec<String>>,
    }

    impl GithubProbe for FixedGithub {
        async fn get(&self, path: &str, _token: &[u8]) -> Result<GithubResponse, AppError> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(path.to_owned());
            }
            let response = if path.contains("code-scanning") {
                GithubResponse {
                    status: 404,
                    message: "no analysis found".to_owned(),
                    accepted_permissions: None,
                }
            } else if path.contains("/issues") {
                GithubResponse {
                    status: 403,
                    message: "Resource not accessible by personal access token".to_owned(),
                    accepted_permissions: Some("issues=read".to_owned()),
                }
            } else {
                GithubResponse {
                    status: 200,
                    message: String::new(),
                    accepted_permissions: None,
                }
            };
            Ok(response)
        }
    }

    /// Test root key: 32 zero bytes, base64. Test value only.
    const ROOT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// The credentials key, derived the same way the app derives it.
    pub fn credentials_key() -> DerivedKey {
        let root = config::parse_encryption_key(ROOT).unwrap();
        crypto::credentials_key(&root).unwrap()
    }

    /// A fresh migrated database under a per-test directory, and the state built on it.
    pub async fn test_state(name: &str) -> (AppState, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "dockward-admin-health-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        let root = config::parse_encryption_key(ROOT).unwrap();
        let state = AppState {
            pool,
            session_key: Arc::new(crypto::session_key(&root).unwrap()),
            csrf_key: Arc::new(crypto::csrf_key(&root).unwrap()),
            public_url: "https://dockward.example.com".to_owned(),
            login_throttle: crate::services::throttle::LoginThrottle::new(),
            login_limiter: RateLimiter::new(10, std::time::Duration::from_secs(60)),
            credentials_key: Arc::new(crypto::credentials_key(&root).unwrap()),
            allow_private_oidc: false,
            allow_private_alerts: false,
            jwks: Arc::new(crate::services::oidc_jwt::JwksCache::new()),
            backup_key: Arc::new(crypto::backup_key(&root).unwrap()),
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
        (state, dir)
    }

    /// Inserts a local user with a placeholder hash. No login happens in these tests.
    pub async fn seed_user(pool: &SqlitePool, id: &str, role: &str) {
        let mut conn = pool.acquire().await.unwrap();
        crate::db::users::insert_local(&mut conn, id, id, None, "not-a-real-hash", role)
            .await
            .unwrap();
    }

    /// Inserts a GitHub credential whose token is encrypted under the credentials key.
    pub async fn seed_github(pool: &SqlitePool, user_id: &str, id: &str, label: &str) {
        let row = CredentialRow {
            id: id.to_owned(),
            service_type: "github".to_owned(),
            label: label.to_owned(),
            base_url: None,
            username: None,
            encrypted_token: encrypt(id, FAKE_GITHUB_TOKEN),
            expires_at: None,
            created_at: None,
        };
        let mut conn = pool.acquire().await.unwrap();
        credential_rows::insert(&mut conn, &row, user_id)
            .await
            .unwrap();
    }

    /// Inserts a source that targets one GitHub repository with `github_cred`.
    pub async fn seed_source(
        pool: &SqlitePool,
        user_id: &str,
        source_id: &str,
        github_cred: &str,
        github_owner: &str,
        github_repo: &str,
    ) {
        let mut conn = pool.acquire().await.unwrap();
        crate::db::sources::insert_for_test(
            &mut conn,
            user_id,
            source_id,
            github_cred,
            github_owner,
            github_repo,
        )
        .await
        .unwrap();
    }

    fn encrypt(id: &str, token: &str) -> String {
        let aad = crypto::aad("user_credentials", "encrypted_token", id);
        crypto::encrypt(&credentials_key(), &aad, token.as_bytes()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::hardening::RateLimiter;
    use crate::auth::crypto;
    use crate::config::parse_encryption_key;
    use crate::services::oidc_jwt::JwksCache;
    use crate::services::throttle::LoginThrottle;
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Sends one `GET /api/v1/admin/health` through the full app router with the given
    /// session token. The router is the real one, so the admin check is the real check.
    async fn get_health(state: crate::api::state::AppState, cookie: Option<&str>) -> (u16, String) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::Request;
        use tower::ServiceExt;

        let mut builder = Request::builder().uri("/api/v1/admin/health");
        if let Some(token) = cookie {
            builder = builder.header(
                "cookie",
                format!("{}={token}", crate::auth::session::SESSION_COOKIE),
            );
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))));
        let response = crate::app(Vec::new(), state.clone())
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Issues a session token for a seeded user, as login does.
    fn session_for(state: &crate::api::state::AppState, user_id: &str, role: &str) -> String {
        let now = crate::auth::session::now_unix().unwrap();
        crate::auth::session::issue(&state.session_key, user_id, role, 0, now).unwrap()
    }

    /// The health route returns `401` with no session, `403` for a regular user, and
    /// `200` for an admin. No credential is seeded, so no probe makes a request.
    #[tokio::test]
    async fn health_is_admin_only() {
        use crate::api::admin::test_support as fake;

        let (state, dir) = fake::test_state("health-admin-only").await;
        fake::seed_user(&state.pool, "u-admin", "admin").await;
        fake::seed_user(&state.pool, "u-user", "user").await;
        let admin_token = session_for(&state, "u-admin", "admin");
        let user_token = session_for(&state, "u-user", "user");

        let (anonymous, _) = get_health(state.clone(), None).await;
        let (regular, _) = get_health(state.clone(), Some(&user_token)).await;
        let (admin, body) = get_health(state.clone(), Some(&admin_token)).await;
        state.pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(anonymous, 401);
        assert_eq!(regular, 403);
        assert_eq!(admin, 200, "{body}");
        assert!(body.contains("\"request\""), "{body}");
        assert!(body.contains("\"source\""), "{body}");
    }

    /// The health body never contains a stored token. GitHub credentials are
    /// seeded with known fake tokens, and the serialized body is checked for both.
    #[tokio::test]
    async fn health_body_contains_no_token() {
        use crate::api::admin::test_support as fake;
        use std::net::IpAddr;

        let (state, dir) = fake::test_state("health-no-token").await;
        fake::seed_user(&state.pool, "u-a", "user").await;
        fake::seed_github(&state.pool, "u-a", "g-a", "github").await;
        fake::seed_source(&state.pool, "u-a", "m-a", "g-a", "octo", "app").await;

        let body = health_body(
            &state,
            &fake::FixedGithub::default(),
            "203.0.113.9".parse::<IpAddr>().unwrap(),
            ClientIpSource::Peer,
        )
        .await
        .unwrap();
        let json = serde_json::to_string(&body).unwrap();
        state.pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert!(!json.contains(fake::FAKE_GITHUB_TOKEN), "{json}");
        assert!(json.contains("\"client_ip\":\"203.0.113.9\""), "{json}");
        assert!(json.contains("\"source\":\"peer\""), "{json}");
    }

    #[test]
    fn create_user_body_debug_redacts_password() {
        // Built at runtime so no literal password assignment appears in the source.
        let fake_secret = ["FAKE_PASSWORD", "_CREATE_1"].concat();
        let body = CreateUserBody {
            username: "fake-new-user".to_owned(),
            email: Some("new@example.test".to_owned()),
            password: fake_secret.clone(),
            role: "user".to_owned(),
        };
        let out = format!("{body:?}");
        assert!(!out.contains(&fake_secret), "password leaked: {out}");
        assert!(out.contains("fake-new-user"), "username missing: {out}");
        assert!(out.contains("new@example.test"), "email missing: {out}");
        assert!(out.contains("user"), "role missing: {out}");
    }

    // Base64 of 32 zero bytes. Test value only.
    const TEST_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// A router over a fresh database. It has one admin and one regular user, each
    /// with a valid session token, and a CSRF token that matches its cookie.
    async fn router(name: &str) -> (axum::Router, sqlx::SqlitePool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "dockward-admin-backup-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::open(&dir).await.unwrap();
        let root = parse_encryption_key(TEST_KEY_B64).unwrap();
        let state = AppState {
            pool: pool.clone(),
            session_key: Arc::new(crypto::session_key(&root).unwrap()),
            csrf_key: Arc::new(crypto::csrf_key(&root).unwrap()),
            public_url: "https://dockward.example.com".to_owned(),
            login_throttle: LoginThrottle::new(),
            login_limiter: RateLimiter::new(10, std::time::Duration::from_secs(60)),
            credentials_key: Arc::new(crypto::credentials_key(&root).unwrap()),
            allow_private_oidc: false,
            allow_private_alerts: false,
            jwks: Arc::new(JwksCache::new()),
            backup_key: Arc::new(crypto::backup_key(&root).unwrap()),
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
        (crate::app(Vec::new(), state), pool, dir)
    }

    /// Inserts an admin and a user, and returns the cookie header for each. The
    /// cookie carries a session token and a matching CSRF token.
    async fn cookies_for(pool: &sqlx::SqlitePool, root_key: &str) -> (String, String) {
        let root = parse_encryption_key(root_key).unwrap();
        let session_key = crypto::session_key(&root).unwrap();
        let csrf_key = crypto::csrf_key(&root).unwrap();
        let now = crate::auth::session::now_unix().unwrap();
        let csrf = crate::auth::csrf::issue(&csrf_key).unwrap();
        let mut conn = pool.acquire().await.unwrap();
        crate::db::users::insert_local(&mut conn, "admin-id", "admin", None, "h", "admin")
            .await
            .unwrap();
        crate::db::users::insert_local(&mut conn, "user-id", "regular", None, "h", "user")
            .await
            .unwrap();
        drop(conn);
        let admin = crate::auth::session::issue(&session_key, "admin-id", "admin", 0, now).unwrap();
        let user = crate::auth::session::issue(&session_key, "user-id", "user", 0, now).unwrap();
        (
            format!("__Host-dockward_session={admin}; __Host-dockward_csrf={csrf}"),
            format!("__Host-dockward_session={user}; __Host-dockward_csrf={csrf}"),
        )
    }

    fn post(cookie: &str, csrf: &str) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/backup")
            .header("cookie", cookie)
            .header("x-csrf-token", csrf)
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))));
        request
    }

    #[tokio::test]
    async fn backup_is_admin_only() {
        let (router, pool, dir) = router("admin-only").await;
        let (admin_cookie, user_cookie) = cookies_for(&pool, TEST_KEY_B64).await;
        let csrf = admin_cookie
            .split("__Host-dockward_csrf=")
            .nth(1)
            .unwrap()
            .to_owned();
        std::fs::create_dir_all(dir.join("backups")).unwrap();

        // A regular user is refused and no file is written.
        let user_response = router
            .clone()
            .oneshot(post(&user_cookie, &csrf))
            .await
            .unwrap();
        assert_eq!(user_response.status(), axum::http::StatusCode::FORBIDDEN);
        let written = std::fs::read_dir(dir.join("backups")).unwrap().count();
        assert_eq!(written, 0, "a regular user wrote a backup file");

        // An admin gets 201 with the file name and the directory, and one backup.run row.
        let admin_response = router.oneshot(post(&admin_cookie, &csrf)).await.unwrap();
        assert_eq!(admin_response.status(), axum::http::StatusCode::CREATED);
        let runs: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'backup.run'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(runs, 1, "the admin backup did not write one backup.run row");
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn channel_request(
        method: &str,
        uri: &str,
        cookie: Option<&str>,
        csrf: &str,
        body: &str,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-csrf-token", csrf);
        if let Some(cookie) = cookie {
            builder = builder.header("cookie", cookie);
        }
        let mut request = builder.body(Body::from(body.to_owned())).unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))));
        request
    }

    #[tokio::test]
    async fn alert_channels_are_admin_only() {
        let (router, pool, dir) = router("alert-channels").await;
        let (admin_cookie, user_cookie) = cookies_for(&pool, TEST_KEY_B64).await;
        let csrf = admin_cookie
            .split("__Host-dockward_csrf=")
            .nth(1)
            .unwrap()
            .to_owned();
        let base = "/api/v1/admin/alert-channels";
        let body = r#"{"kind":"webhook","enabled":true,"config":{"url":"https://hooks.example.test/FAKE_ROUTE_TOKEN"}}"#;

        // No session is 401 and a regular user is 403, on every method.
        for (method, uri) in [
            ("GET", base.to_owned()),
            ("POST", base.to_owned()),
            ("PUT", format!("{base}/some-id")),
        ] {
            // No session cookie, but a valid CSRF pair, so the session check is what answers.
            let csrf_only = format!("__Host-dockward_csrf={csrf}");
            let anonymous = router
                .clone()
                .oneshot(channel_request(method, &uri, Some(&csrf_only), &csrf, body))
                .await
                .unwrap();
            assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED, "{method}");
            let regular = router
                .clone()
                .oneshot(channel_request(
                    method,
                    &uri,
                    Some(&user_cookie),
                    &csrf,
                    body,
                ))
                .await
                .unwrap();
            assert_eq!(regular.status(), StatusCode::FORBIDDEN, "{method}");
        }
        let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alert_channels")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored, 0, "a refused request created a channel");

        // An admin creates (201), lists (200), updates (200), and gets 404 and 422.
        let created = router
            .clone()
            .oneshot(channel_request(
                "POST",
                base,
                Some(&admin_cookie),
                &csrf,
                body,
            ))
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(created.into_body(), 1 << 20)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(
            !text.contains("FAKE_ROUTE_TOKEN"),
            "the route token leaked into the create response"
        );
        let id = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();

        let listed = router
            .clone()
            .oneshot(channel_request("GET", base, Some(&admin_cookie), &csrf, ""))
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(listed.into_body(), 1 << 20)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("FAKE_ROUTE_TOKEN"));

        let updated = router
            .clone()
            .oneshot(channel_request(
                "PUT",
                &format!("{base}/{id}"),
                Some(&admin_cookie),
                &csrf,
                r#"{"enabled":false}"#,
            ))
            .await
            .unwrap();
        assert_eq!(updated.status(), StatusCode::OK);
        let missing = router
            .clone()
            .oneshot(channel_request(
                "PUT",
                &format!("{base}/no-such-id"),
                Some(&admin_cookie),
                &csrf,
                r#"{"enabled":false}"#,
            ))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let invalid = router
            .oneshot(channel_request(
                "POST",
                base,
                Some(&admin_cookie),
                &csrf,
                r#"{"kind":"webhook","enabled":true,"config":{"url":"http://hooks.example.test/x"}}"#,
            ))
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `GET /api/v1/admin/jobs` through the full router. No session is `401`, a regular user
    /// is `403`, and an admin is `200` with the paged shape. `kind` outside the allow-list
    /// is `400`, checked before any SQL.
    #[tokio::test]
    async fn admin_jobs_is_admin_only() {
        use crate::api::admin::test_support as fake;

        let (state, dir) = fake::test_state("admin-jobs").await;
        fake::seed_user(&state.pool, "u-admin", "admin").await;
        fake::seed_user(&state.pool, "u-user", "user").await;
        crate::db::job_runs::insert(
            &state.pool,
            &crate::db::job_runs::JobRun {
                id: "run-1".to_owned(),
                job_kind: "retention".to_owned(),
                started_at: 1_000,
                finished_at: Some(1_010),
                status: "done".to_owned(),
                processed_count: 3,
                error_summary: None,
                scanner: None,
            },
        )
        .await
        .unwrap();
        let admin_token = session_for(&state, "u-admin", "admin");
        let user_token = session_for(&state, "u-user", "user");

        let (anonymous, _) = get_path(state.clone(), "/api/v1/admin/jobs", None).await;
        let (regular, _) = get_path(state.clone(), "/api/v1/admin/jobs", Some(&user_token)).await;
        let (admin, body) = get_path(state.clone(), "/api/v1/admin/jobs", Some(&admin_token)).await;
        let (bad_kind, _) = get_path(
            state.clone(),
            "/api/v1/admin/jobs?kind=unknown",
            Some(&admin_token),
        )
        .await;
        state.pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(anonymous, 401);
        assert_eq!(regular, 403);
        assert_eq!(admin, 200, "{body}");
        assert!(body.contains("\"job_kind\":\"retention\""), "{body}");
        assert_eq!(bad_kind, 400);
    }

    /// A GET through the full router with an optional session cookie. Returns the status
    /// and the body text.
    async fn get_path(
        state: crate::api::state::AppState,
        uri: &str,
        cookie: Option<&str>,
    ) -> (u16, String) {
        use axum::extract::ConnectInfo;
        let mut builder = Request::builder().uri(uri);
        if let Some(token) = cookie {
            builder = builder.header(
                "cookie",
                format!("{}={token}", crate::auth::session::SESSION_COOKIE),
            );
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                8080,
            ))));
        let response = crate::app(Vec::new(), state.clone())
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }
}
