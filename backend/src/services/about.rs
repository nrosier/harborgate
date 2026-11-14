//! The About data: the dockward version and the bundled Trivy and Grype versions
//! (`specs/api.md`, About). The scanner versions are read once at startup by running
//! `trivy --version` and `grype version`. A failed read is `None`, and startup continues.
//!
//! Only the binary name and the outcome are logged. The output of the binary is parsed for a
//! version token and then dropped, so nothing it prints reaches a log line.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde::Serialize;
use sqlx::SqlitePool;
use tokio::process::Command;

use crate::db::scanner_releases;
use crate::error::AppError;
use crate::services::scanner::selection::{ScannerPrograms, Selected};
use crate::services::scanner::version::Version;
use crate::services::scanner::{Scanner, environment};

/// How long one version read may take.
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest version token that is accepted.
const MAX_VERSION_LEN: usize = 64;

/// The body of `GET /api/v1/about`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct About {
    pub dockward: String,
    pub trivy: Option<String>,
    pub grype: Option<String>,
}

impl About {
    /// Reads both scanner versions. The two reads run one after the other, each with its own
    /// timeout.
    pub async fn read(cache_root: &Path, trivy: &Path, grype: &Path) -> Self {
        Self {
            dockward: env!("CARGO_PKG_VERSION").to_owned(),
            trivy: read_version(Scanner::Trivy, trivy, &["--version"], cache_root).await,
            grype: read_version(Scanner::Grype, grype, &["version"], cache_root).await,
        }
    }

    /// The production read: the pinned executables, with the data directory's scanner cache.
    pub async fn read_bundled(data_dir: &Path) -> Self {
        Self::read(
            &data_dir.join("scanner-cache"),
            Scanner::Trivy.bundled_program(),
            Scanner::Grype.bundled_program(),
        )
        .await
    }

    /// The bundled Trivy and Grype versions as parsed versions, `None` where the read failed or
    /// the text is not a plain `vMAJOR.MINOR.PATCH`. The scanner selection and the upstream
    /// check compare against these (#390).
    pub fn bundled_versions(&self) -> [Option<Version>; 2] {
        [
            self.trivy.as_deref().and_then(Version::parse),
            self.grype.as_deref().and_then(Version::parse),
        ]
    }
}

/// The body of `GET /api/v1/about`: the startup versions and the live scanner state (#390).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AboutView {
    #[serde(flatten)]
    pub versions: About,
    pub scanners: ScannersView,
}

/// The state of both scanners.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ScannersView {
    pub trivy: ScannerView,
    pub grype: ScannerView,
}

/// The state of one scanner. Versions are `vX.Y.Z`. Holds no path.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ScannerView {
    /// `bundled` or `downloaded`: the binary scans use now.
    pub in_use: &'static str,
    /// The downloaded version in use, or `null` when the bundled one runs.
    pub downloaded_version: Option<String>,
    /// A downloaded version that failed to launch and is no longer used, or `null`.
    pub broken_version: Option<String>,
    /// The latest stable upstream release from the last successful daily check, or `null`.
    pub latest_version: Option<String>,
    /// True when that release is newer than the bundled scanner.
    pub update_available: bool,
    /// When the last successful check ran (RFC 3339), or `null`.
    pub checked_at: Option<String>,
}

/// Builds the About body from the startup versions, the live selection and the stored checks.
pub async fn view(
    about: &About,
    programs: &ScannerPrograms,
    pool: &SqlitePool,
) -> Result<AboutView, AppError> {
    Ok(AboutView {
        versions: about.clone(),
        scanners: ScannersView {
            trivy: scanner_view(Scanner::Trivy, programs, pool).await?,
            grype: scanner_view(Scanner::Grype, programs, pool).await?,
        },
    })
}

async fn scanner_view(
    scanner: Scanner,
    programs: &ScannerPrograms,
    pool: &SqlitePool,
) -> Result<ScannerView, AppError> {
    let state = programs.state(scanner);
    let (in_use, downloaded_version) = match state.selected {
        Selected::Bundled => ("bundled", None),
        Selected::Downloaded(version) => ("downloaded", Some(version.tagged())),
    };
    let release = scanner_releases::get(pool, scanner.key()).await?;
    let latest = release
        .as_ref()
        .and_then(|row| Version::parse(&row.latest_version));
    let checked_at = match &release {
        Some(row) => Some(crate::services::time::rfc3339(row.checked_at)?),
        None => None,
    };
    Ok(ScannerView {
        in_use,
        downloaded_version,
        broken_version: state.broken.map(|version| version.tagged()),
        latest_version: latest.map(|version| version.tagged()),
        // Newer than the bundled scanner, and not already installed: a downloaded version at or
        // above the latest release needs no update.
        update_available: release.is_some_and(|row| row.newer_than_bundled)
            && latest.is_some_and(|latest| match state.selected {
                Selected::Downloaded(in_use) => latest > in_use,
                Selected::Bundled => true,
            }),
        checked_at,
    })
}

async fn read_version(
    scanner: Scanner,
    program: &Path,
    args: &[&str],
    cache_root: &Path,
) -> Option<String> {
    let name = scanner.key();
    let version = run(scanner, program, args, cache_root).await;
    match &version {
        Some(_) => tracing::info!(binary = name, "scanner version read"),
        None => tracing::warn!(binary = name, "scanner version could not be read"),
    }
    version
}

async fn run(scanner: Scanner, program: &Path, args: &[&str], cache_root: &Path) -> Option<String> {
    if !program.is_absolute() {
        return None;
    }
    let child = Command::new(program)
        .args(args)
        .env_clear()
        .envs(environment(cache_root, scanner, true))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    // On a timeout the future is dropped, and `kill_on_drop` ends the child.
    let output = tokio::time::timeout(READ_TIMEOUT, child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_version(&String::from_utf8_lossy(&output.stdout))
}

/// Finds the `Version: X` line of the output and returns `vX`. Both scanners print it. A token
/// that is empty, too long or holds anything but letters, digits and `.+-_` is rejected.
pub fn parse_version(output: &str) -> Option<String> {
    let token = output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim().eq_ignore_ascii_case("version")).then(|| value.trim())
    })?;
    let bare = token.strip_prefix('v').unwrap_or(token);
    let valid = !bare.is_empty()
        && bare.len() <= MAX_VERSION_LEN
        && bare
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | '_'));
    valid.then(|| format!("v{bare}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("dockward-about-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parses_both_scanner_formats() {
        let trivy = "Version: 0.76.2\nVulnerability DB:\n  Version: 2\n";
        assert_eq!(parse_version(trivy).as_deref(), Some("v0.76.2"));
        let grype =
            "Application:         grype\nVersion:             0.121.3\nBuildDate:           x\n";
        assert_eq!(parse_version(grype).as_deref(), Some("v0.121.3"));
        assert_eq!(parse_version("Version: v1.2.3").as_deref(), Some("v1.2.3"));
    }

    #[test]
    fn rejects_odd_output() {
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("Version:"), None);
        assert_eq!(parse_version("no version here"), None);
        assert_eq!(parse_version("Version: 1.0 <script>"), None);
        assert_eq!(parse_version(&format!("Version: {}", "9".repeat(65))), None);
    }

    #[tokio::test]
    async fn reads_both_versions_from_the_binaries() {
        let dir = temp("ok");
        let trivy = script(
            &dir,
            "trivy",
            "[ \"$1\" = --version ] && echo 'Version: 0.76.2'",
        );
        let grype = script(
            &dir,
            "grype",
            "[ \"$1\" = version ] && echo 'Version:   0.121.3'",
        );
        let about = About::read(&dir, &trivy, &grype).await;
        assert_eq!(about.dockward, env!("CARGO_PKG_VERSION"));
        assert_eq!(about.trivy.as_deref(), Some("v0.76.2"));
        assert_eq!(about.grype.as_deref(), Some("v0.121.3"));
    }

    #[tokio::test]
    async fn a_failed_read_is_none_and_does_not_stop_the_other() {
        let dir = temp("fail");
        let trivy = script(&dir, "trivy", "echo 'Version: 0.76.2'; exit 3");
        let grype = script(&dir, "grype", "echo 'Version: 0.121.3'");
        let missing = dir.join("absent");
        let about = About::read(&dir, &trivy, &grype).await;
        assert_eq!(about.trivy, None);
        assert_eq!(about.grype.as_deref(), Some("v0.121.3"));
        let about = About::read(&dir, &missing, &missing).await;
        assert_eq!((about.trivy, about.grype), (None, None));
        assert!(!about.dockward.is_empty());
    }

    #[tokio::test]
    async fn a_hung_binary_times_out() {
        let dir = temp("hang");
        let trivy = script(&dir, "trivy", "sleep 30");
        let started = std::time::Instant::now();
        let version = read_version(Scanner::Trivy, &trivy, &["--version"], &dir).await;
        assert_eq!(version, None);
        assert!(started.elapsed() < Duration::from_secs(15));
    }
}
