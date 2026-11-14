//! Shared application state for handlers and extractors.

use std::path::PathBuf;
use std::sync::Arc;

use sqlx::SqlitePool;

use crate::api::hardening::RateLimiter;
use crate::auth::crypto::DerivedKey;
use crate::services::oidc_jwt::JwksCache;
use crate::services::throttle::LoginThrottle;

/// Pool and derived session key. The session key is kept behind an `Arc` because
/// the derived key is not `Clone`.
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub session_key: Arc<DerivedKey>,
    pub csrf_key: Arc<DerivedKey>,
    /// `DOCKWARD_PUBLIC_URL`, the origin that login and setup requests must match.
    pub public_url: String,
    /// Failed-login delay per (account, client IP).
    pub login_throttle: LoginThrottle,
    /// Login attempts per client IP: 10 per minute (`specs/security.md`, Hardening).
    pub login_limiter: RateLimiter,
    /// Derived credential key. It decrypts the OIDC client secret.
    pub credentials_key: Arc<DerivedKey>,
    /// `DOCKWARD_ALLOW_PRIVATE_OIDC`. The private-range opt-out for OIDC targets.
    pub allow_private_oidc: bool,
    /// The JWKS cache for ID token verification.
    pub jwks: Arc<JwksCache>,
    /// `DOCKWARD_ALLOW_PRIVATE_ALERTS`. The private-range opt-out for alert webhook targets.
    pub allow_private_alerts: bool,
    /// Derived backup key. It seals and opens backup files (`specs/security.md`, Derived keys).
    pub backup_key: Arc<DerivedKey>,
    /// `DOCKWARD_DATA_DIR`. The temporary `VACUUM INTO` copy is written here.
    pub data_dir: PathBuf,
    /// `DOCKWARD_BACKUP_DIR`. Encrypted backups are written here.
    pub backup_dir: PathBuf,
    /// The GitHub Issues client, built once. The manual issue route uses it.
    pub issues_client: Arc<crate::services::github_issues::GithubIssues>,
    /// The application log buffer and the global level controller
    /// (`specs/security.md`, Application log).
    pub app_log: Arc<crate::services::app_log::AppLog>,
    /// The live GitHub API base URL and web URL (`specs/integrations.md`, "GitHub base URL").
    /// Every GitHub client holds a clone, so an admin change applies without a restart.
    pub github: crate::services::github_url::GithubTarget,
    /// Discovery for the manual scan route (`specs/spinoff-local-scan.md`, section 10).
    pub discovery: Arc<crate::services::discovery::Discovery>,
    /// Manual scans: 1 per source per 5 minutes, held in memory (section 10, decision 17).
    pub scan_limiter: RateLimiter,
    /// Routes that call a registry for a list or a test, or resolve an entered host: 60 per
    /// minute per user, held in memory (section 10).
    pub registry_limiter: RateLimiter,
    /// Wrong TOTP codes per account: 5 per 15 minutes, counted on failure only. The sixth
    /// attempt in the window is refused and the lockout is audited. Held in memory, so a restart
    /// clears it (`specs/security.md`, "Two-factor sign-in (TOTP)").
    pub totp_limiter: RateLimiter,
    /// The dockward version and the bundled scanner versions, read once at startup
    /// (`specs/api.md`, About).
    pub about: Arc<crate::services::about::About>,
    /// The live scanner selection: the bundled binaries or a newer downloaded one, and a
    /// downloaded version marked broken (#390). Shared with the scan job.
    pub scanner_programs: Arc<crate::services::scanner::selection::ScannerPrograms>,
}
