//! OIDC routes. Sources: `specs/api.md` (Auth, Admin), `specs/security.md` (OIDC,
//! Sessions, Login CSRF). Admin settings need an `admin` session. The sign-in routes
//! are public. Every failure is a generic error, so the response does not say which
//! check failed.

use std::fmt;

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::LOCATION, header::SET_COOKIE},
    response::{IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};

use crate::api::auth::{AdminUser, UserResponse, session_response};
use crate::api::state::AppState;
use crate::error::AppError;
use crate::models::user::User;
use crate::services::audit::Actor;
use crate::services::oidc::{self, Callback, HttpProvider, OidcSettings};
use crate::services::oidc_settings::{self, OidcSettingsBody};

/// Name of the short-lived cookie that holds `state`, the PKCE verifier, and `nonce`.
pub const OIDC_COOKIE: &str = "__Host-dockward_oidc";
/// Lifetime of the sign-in cookie: 10 minutes (`specs/security.md`, Sessions).
pub const OIDC_COOKIE_MAX_AGE_SECS: u32 = 10 * 60;

/// Response shape for `GET` and `PUT /api/v1/admin/oidc`. The secret is never here.
#[derive(Debug, Serialize)]
pub struct OidcSettingsView {
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub role_claim: Option<String>,
    pub admin_group: Option<String>,
    pub user_group: Option<String>,
    pub client_secret_set: bool,
    pub oidc_only_users: bool,
}

impl From<OidcSettings> for OidcSettingsView {
    fn from(s: OidcSettings) -> Self {
        Self {
            issuer_url: s.issuer_url,
            client_id: s.client_id,
            role_claim: s.role_claim,
            admin_group: s.admin_group,
            user_group: s.user_group,
            client_secret_set: s.client_secret_set,
            oidc_only_users: s.oidc_only_users,
        }
    }
}

/// `GET /api/v1/admin/oidc`.
pub async fn get_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<OidcSettingsView>, AppError> {
    let settings = oidc_settings::get(&state.pool).await?;
    Ok(Json(settings.into()))
}

/// `PUT /api/v1/admin/oidc`. Writes the settings and audits the change. A toggle on
/// with incomplete settings is `422`.
pub async fn put_settings(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    body: axum::body::Bytes,
) -> Result<Json<OidcSettingsView>, AppError> {
    let body: OidcSettingsBody = serde_json::from_slice(&body)
        .map_err(|_| AppError::InvalidRequest("The request body is not valid.".to_owned()))?;
    let actor = Actor {
        user_id: Some(admin.id),
        username: admin.username,
    };
    let saved = oidc_settings::save(&state.pool, &state.credentials_key, &actor, body).await?;
    Ok(Json(saved.into()))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    /// The provider's `error` parameter, for example when the user denied consent.
    pub error: Option<String>,
}

const REDACTED: &str = "<redacted>";

/// The `oidc_error` value for a provider `error` parameter. The provider's own text is
/// never copied into the redirect URL.
const PROVIDER_ERROR_CODE: &str = "provider_error";

impl fmt::Debug for CallbackQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallbackQuery")
            .field("code", &REDACTED)
            .field("state", &REDACTED)
            .field("error", &REDACTED)
            .finish()
    }
}

/// The redirect URI sent to the provider. It is built from `DOCKWARD_PUBLIC_URL`.
fn redirect_uri(state: &AppState) -> String {
    redirect_uri_for(&state.public_url)
}

/// The callback URL for a public origin. Split out so the test can assert the value.
fn redirect_uri_for(public_url: &str) -> String {
    format!("{public_url}/api/v1/auth/oidc/callback")
}

/// `GET /api/v1/auth/oidc/start`. Redirects to the issuer and sets the sign-in cookie.
/// Returns `404` while OIDC is not fully configured.
pub async fn start(State(state): State<AppState>) -> Result<Response, AppError> {
    let settings = oidc::load_settings(&state.pool).await?;
    if !settings.is_complete() {
        return Err(AppError::NotFound);
    }
    let issuer_raw = settings.issuer_url.clone().unwrap_or_default();
    let client_id = settings.client_id.clone().unwrap_or_default();
    let provider = http_provider(&state)?;
    let (url, pending) =
        oidc::begin_login(&provider, &issuer_raw, &client_id, &redirect_uri(&state)).await?;
    let value = pending.to_cookie();
    let cookie = format!(
        "{OIDC_COOKIE}={value}; Max-Age={OIDC_COOKIE_MAX_AGE_SECS}; Path=/; HttpOnly; Secure; SameSite=Lax"
    );
    let mut response = Redirect::to(url.as_str()).into_response();
    *response.status_mut() = StatusCode::FOUND;
    let header = cookie.parse().map_err(|_| AppError::InternalError)?;
    response.headers_mut().append(SET_COOKIE, header);
    Ok(response)
}

/// `GET /api/v1/auth/oidc/callback`. Verifies `state`, exchanges the code, verifies the
/// ID token and `nonce`, provisions or updates the user, and signs them in. Returns `404`
/// while OIDC is not configured. Every other outcome is `302`: success goes to `/`, and a
/// failure or a provider `error` goes to `/?oidc_error=<code>`. The sign-in cookie is
/// cleared on every outcome.
pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    let settings = oidc::load_settings(&state.pool).await?;
    if !settings.is_complete() {
        return Err(AppError::NotFound);
    }
    let mut response = if query.error.is_some() {
        error_redirect(PROVIDER_ERROR_CODE)?
    } else {
        match sign_in(&state, &settings, &headers, &query).await {
            Ok(response) => response,
            Err(err) => error_redirect(err.code())?,
        }
    };
    clear_pending(&mut response)?;
    Ok(response)
}

/// The sign-in itself: checks the query, completes the callback, and sets the session
/// cookies on the `302` to `/`.
async fn sign_in(
    state: &AppState,
    settings: &OidcSettings,
    headers: &HeaderMap,
    query: &CallbackQuery,
) -> Result<Response, AppError> {
    let code = query.code.as_deref().ok_or(AppError::InvalidRequest(
        "The sign-in response is missing a code.".to_owned(),
    ))?;
    let state_param = query.state.as_deref().ok_or(AppError::InvalidRequest(
        "The sign-in response is missing a state.".to_owned(),
    ))?;
    let cookie = crate::auth::session::read_cookie(headers, OIDC_COOKIE);
    let secret_stored = oidc_secret(state).await?;
    let client_secret = oidc::open_client_secret(&state.credentials_key, &secret_stored)?;
    let provider = http_provider(state)?;
    let redirect = redirect_uri(state);
    let row = oidc::complete_callback(
        &state.pool,
        &provider,
        &state.jwks,
        settings,
        Callback {
            cookie,
            state: state_param,
            code,
            redirect_uri: &redirect,
            client_secret: client_secret.as_str(),
        },
    )
    .await?;
    let view = User::try_from(row.clone())?;
    let mut response =
        session_response(state, &row, StatusCode::FOUND, UserResponse { user: view })?;
    *response.body_mut() = axum::body::Body::empty();
    response
        .headers_mut()
        .insert(LOCATION, HeaderValue::from_static("/"));
    Ok(response)
}

/// A `302` to the login page with the error code. `code` is a fixed snake_case value
/// from `AppError::code` or `PROVIDER_ERROR_CODE`, so it is safe in the URL.
fn error_redirect(code: &str) -> Result<Response, AppError> {
    let location = HeaderValue::try_from(format!("/?oidc_error={code}"))
        .map_err(|_| AppError::InternalError)?;
    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(LOCATION, location);
    Ok(response)
}

/// Clears the sign-in cookie on the callback response, so the state is single-use.
fn clear_pending(response: &mut Response) -> Result<(), AppError> {
    let cleared = format!("{OIDC_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax");
    let header = cleared.parse().map_err(|_| AppError::InternalError)?;
    response.headers_mut().append(SET_COOKIE, header);
    Ok(())
}

/// The stored, encrypted client secret for the token request.
async fn oidc_secret(state: &AppState) -> Result<String, AppError> {
    crate::db::config::get(&state.pool, oidc::CLIENT_SECRET_KEY)
        .await?
        .ok_or(AppError::NotFound)
}

/// The production provider with the operator's private-range opt-out.
fn http_provider(state: &AppState) -> Result<HttpProvider, AppError> {
    HttpProvider::new(state.allow_private_oidc)
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header::LOCATION, header::SET_COOKIE};
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::api::hardening::RateLimiter;
    use crate::api::state::AppState;
    use crate::auth::crypto;
    use crate::config::parse_encryption_key;
    use crate::services::oidc::OidcSettings;
    use crate::services::oidc_jwt::JwksCache;
    use crate::services::throttle::LoginThrottle;
    use std::time::Duration;

    use super::{CallbackQuery, OIDC_COOKIE, OidcSettingsView};

    #[test]
    fn callback_query_debug_redacts_code_and_state() {
        // Fixed fake values. Not real credentials.
        const FAKE_CODE: &str = "fake-auth-code-value";
        const FAKE_STATE: &str = "fake-state-value";
        const FAKE_ERROR: &str = "fake-provider-error-text";

        let query = CallbackQuery {
            code: Some(FAKE_CODE.to_owned()),
            state: Some(FAKE_STATE.to_owned()),
            error: Some(FAKE_ERROR.to_owned()),
        };
        let text = format!("{query:?}");
        assert!(!text.contains(FAKE_CODE), "code leaked: {text}");
        assert!(!text.contains(FAKE_STATE), "state leaked: {text}");
        assert!(!text.contains(FAKE_ERROR), "error leaked: {text}");
        assert!(
            text.contains("CallbackQuery"),
            "struct name missing: {text}"
        );
        assert!(
            text.contains("<redacted>"),
            "redaction marker missing: {text}"
        );
    }

    /// Test-only key material. The value is fake and never logged.
    const TEST_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    async fn router(name: &str) -> (axum::Router, sqlx::SqlitePool, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("dockward-oidc-route-{name}-{}", std::process::id()));
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
            login_limiter: RateLimiter::new(10, Duration::from_secs(60)),
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

    fn peer(builder: axum::http::request::Builder) -> axum::http::request::Builder {
        builder.extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            8080,
        ))))
    }

    async fn status_of(router: &axum::Router, uri: &str) -> StatusCode {
        let request = peer(Request::builder().method("GET").uri(uri))
            .body(Body::empty())
            .unwrap();
        router.clone().oneshot(request).await.unwrap().status()
    }

    #[tokio::test]
    async fn start_and_callback_are_not_found_while_oidc_is_unconfigured() {
        let (router, pool, dir) = router("unconfigured").await;
        let start = status_of(&router, "/api/v1/auth/oidc/start").await;
        let callback = status_of(&router, "/api/v1/auth/oidc/callback?code=x&state=y").await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(start, StatusCode::NOT_FOUND);
        assert_eq!(callback, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn admin_oidc_routes_require_a_session() {
        let (router, pool, dir) = router("admin-auth").await;
        let get = status_of(&router, "/api/v1/admin/oidc").await;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(get, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn setup_status_reports_oidc_disabled_until_configured() {
        let (router, pool, dir) = router("setup-status").await;
        let request = peer(
            Request::builder()
                .method("GET")
                .uri("/api/v1/auth/setup-status"),
        )
        .body(Body::empty())
        .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(json["oidc_enabled"], serde_json::Value::Bool(false));
    }

    /// Inserts a local admin directly and returns the cookie header and a matching CSRF
    /// header value. Test values only.
    async fn admin_cookies(pool: &sqlx::SqlitePool) -> (String, String) {
        let root = parse_encryption_key(TEST_KEY_B64).unwrap();
        let inserted = crate::db::setup::insert_first_admin(
            pool,
            "admin-test-id",
            "admin",
            None,
            "not-a-real-hash",
        )
        .await
        .unwrap();
        assert!(inserted, "the first admin should be inserted");
        let session_key = crypto::session_key(&root).unwrap();
        let csrf_key = crypto::csrf_key(&root).unwrap();
        let now = crate::auth::session::now_unix().unwrap();
        let token =
            crate::auth::session::issue(&session_key, "admin-test-id", "admin", 0, now).unwrap();
        let csrf_value = crate::auth::csrf::issue(&csrf_key).unwrap();
        (
            format!("__Host-dockward_session={token}; __Host-dockward_csrf={csrf_value}"),
            csrf_value,
        )
    }

    #[tokio::test]
    async fn put_oidc_only_with_incomplete_settings_is_422() {
        let (router, pool, dir) = router("put-422").await;
        let (cookies, csrf) = admin_cookies(&pool).await;
        // Issuer and client ID are set, but there is no secret, role claim, or group.
        let body = serde_json::json!({
            "issuer_url": "https://issuer.example.com",
            "client_id": "dockward-test",
            "oidc_only_users": true,
        });
        let request = peer(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/oidc")
                .header("content-type", "application/json")
                .header("cookie", cookies)
                .header("x-csrf-token", csrf),
        )
        .body(Body::from(body.to_string()))
        .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let stored = crate::db::config::get(&pool, crate::services::oidc::ONLY_USERS_KEY)
            .await
            .unwrap();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            stored, None,
            "a refused save must not enable OIDC-only login"
        );
    }

    #[test]
    fn redirect_uri_is_built_from_the_public_url() {
        // `config` strips the trailing slash from DOCKWARD_PUBLIC_URL before it reaches
        // AppState, so the redirect URI is the origin plus the callback path.
        assert_eq!(
            super::redirect_uri_for("https://dockward.example.com"),
            "https://dockward.example.com/api/v1/auth/oidc/callback"
        );
        assert_eq!(
            super::redirect_uri_for("http://localhost:8080"),
            "http://localhost:8080/api/v1/auth/oidc/callback"
        );
    }

    #[test]
    fn settings_view_never_carries_the_client_secret_field() {
        let view = OidcSettingsView::from(OidcSettings {
            client_secret_set: true,
            ..OidcSettings::default()
        });
        let text = serde_json::to_string(&view).unwrap();
        assert!(text.contains("client_secret_set"));
        assert!(
            !text.contains("client_secret\""),
            "the secret value is never serialised"
        );
        assert!(!text.contains("client_secret_encrypted"));
    }

    /// Stores complete OIDC settings with a sealed client secret. Test values only. No
    /// callback in these tests reaches the provider.
    async fn configure_oidc(pool: &sqlx::SqlitePool) {
        let root = parse_encryption_key(TEST_KEY_B64).unwrap();
        let key = crypto::credentials_key(&root).unwrap();
        let sealed = crate::services::oidc::seal_client_secret(&key, "test-client-secret").unwrap();
        let mut conn = pool.acquire().await.unwrap();
        for (name, value) in [
            (crate::services::oidc::ISSUER_KEY, "https://idp.example.com"),
            (crate::services::oidc::CLIENT_ID_KEY, "dockward-test"),
            (crate::services::oidc::ROLE_CLAIM_KEY, "groups"),
            (crate::services::oidc::USER_GROUP_KEY, "test-users"),
        ] {
            crate::db::config::upsert(&mut conn, name, value, false)
                .await
                .unwrap();
        }
        crate::db::config::upsert(
            &mut conn,
            crate::services::oidc::CLIENT_SECRET_KEY,
            &sealed,
            true,
        )
        .await
        .unwrap();
    }

    /// Sends a callback request with the given query and the sign-in cookie for `pending`.
    async fn callback_response(
        router: &axum::Router,
        query: &str,
        cookie: &str,
    ) -> axum::response::Response {
        let request = peer(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/auth/oidc/callback?{query}"))
                .header("cookie", format!("{OIDC_COOKIE}={cookie}")),
        )
        .body(Body::empty())
        .unwrap();
        router.clone().oneshot(request).await.unwrap()
    }

    /// True when some `Set-Cookie` header clears the sign-in cookie.
    fn clears_oidc_cookie(response: &axum::response::Response) -> bool {
        response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| value.starts_with(&format!("{OIDC_COOKIE}=; Max-Age=0")))
    }

    #[tokio::test]
    async fn failed_callback_clears_the_cookie_and_redirects() {
        let (router, pool, dir) = router("failed-callback").await;
        configure_oidc(&pool).await;
        // The cookie holds a different state from the query, so the callback fails before
        // any provider request.
        let pending = match crate::services::oidc::Pending::new() {
            Ok(p) => p,
            Err(_) => panic!("the OS random source must work in tests"),
        };
        let response = callback_response(
            &router,
            "code=test-code&state=test-other-state",
            &pending.to_cookie(),
        )
        .await;
        let status = response.status();
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let cleared = clears_oidc_cookie(&response);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(status, StatusCode::FOUND);
        assert_eq!(location.as_deref(), Some("/?oidc_error=unauthenticated"));
        assert!(
            cleared,
            "the sign-in cookie must be cleared on a failed callback"
        );
    }

    #[tokio::test]
    async fn provider_error_redirects_with_provider_error() {
        let (router, pool, dir) = router("provider-error").await;
        configure_oidc(&pool).await;
        let pending = match crate::services::oidc::Pending::new() {
            Ok(p) => p,
            Err(_) => panic!("the OS random source must work in tests"),
        };
        // The provider's own text is not copied into the redirect.
        let response = callback_response(
            &router,
            &format!(
                "error=access_denied&error_description=test-consent-text&state={}",
                pending.state
            ),
            &pending.to_cookie(),
        )
        .await;
        let status = response.status();
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let cleared = clears_oidc_cookie(&response);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(status, StatusCode::FOUND);
        assert_eq!(location.as_deref(), Some("/?oidc_error=provider_error"));
        assert!(
            cleared,
            "the sign-in cookie must be cleared on a provider error"
        );
    }
}
