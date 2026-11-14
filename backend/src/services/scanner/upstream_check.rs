//! The daily upstream check of the scanners (#390, phase 1).
//!
//! Once a day, in the background, dockward asks the GitHub latest-release API for each scanner,
//! `GET https://api.github.com/repos/aquasecurity/trivy/releases/latest` and
//! `GET https://api.github.com/repos/anchore/grype/releases/latest`. That route names the latest
//! release that is neither a draft nor a pre-release; a body that says otherwise, or a tag that
//! is not a plain `vMAJOR.MINOR.PATCH`, is not an answer. The tag is compared with the bundled
//! version and the result (scanner, latest version, newer or not, checked_at) is stored in
//! `scanner_releases` (migration 0017).
//!
//! A failure (unreachable, a status other than 200, a body over the cap or unreadable, a
//! pre-release, a malformed tag, an unknown bundled version) is logged with the scanner key and
//! the outcome only, and records nothing new: the last good answer stays. The next day asks
//! again. The check runs on its own task and never takes the scanner lock, so a scan never waits
//! for it.
//!
//! What leaves dockward: one `GET` per scanner to the fixed host `api.github.com` through the
//! guarded client with the class [`TargetClass::ScannerRelease`], with the headers `Accept`,
//! `User-Agent` and `X-GitHub-Api-Version` only. No token, and the configured GitHub base URL is
//! not used. No response body reaches a log. Nothing is downloaded (phase 2).

use std::time::Duration;

use serde::Deserialize;
use sqlx::SqlitePool;
use tokio::sync::watch;

use super::Scanner;
use super::version::Version;
use crate::db::scanner_releases;
use crate::services::outbound::{self, OutboundClient, TargetClass};
use crate::worker::now_secs;

/// The GitHub API host, always the public one.
const GITHUB_BASE: &str = "https://api.github.com";
/// One request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// A release document larger than this is not read. Trivy and Grype releases list many assets.
const BODY_MAX_BYTES: usize = 4 << 20;
/// Time between checks: once a day.
pub const INTERVAL: Duration = Duration::from_secs(86_400);
/// Delay before the first check after start, so startup does not reach the network at once.
const FIRST_DELAY: Duration = Duration::from_secs(300);

/// Both scanners, in the order they are checked.
const SCANNERS: [Scanner; 2] = [Scanner::Trivy, Scanner::Grype];

/// The upstream GitHub repository of a scanner.
pub fn upstream_repo(scanner: Scanner) -> &'static str {
    match scanner {
        Scanner::Trivy => "aquasecurity/trivy",
        Scanner::Grype => "anchore/grype",
    }
}

#[derive(Debug, Clone)]
enum Mode {
    /// The public GitHub API. Tests never build it.
    #[cfg_attr(test, allow(dead_code))]
    Live,
    /// A loopback TLS server stands in for `api.github.com`. Tests only.
    #[cfg(test)]
    Local {
        base: String,
        root: reqwest::Certificate,
    },
}

/// The upstream check. Cheap to clone.
#[derive(Debug, Clone)]
pub struct UpstreamCheck {
    mode: Mode,
}

/// The fields of a GitHub release that are read.
#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
}

/// What one check of one scanner found. The text is the logged outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A newer stable release than the bundled one exists, and was recorded.
    Newer(Version),
    /// The latest stable release is not newer than the bundled one, and was recorded.
    Current(Version),
    /// No usable answer; nothing recorded.
    Unavailable,
    /// The bundled version is unknown, so nothing can be compared; nothing recorded.
    BundledUnknown,
    /// The answer could not be stored.
    NotStored,
}

impl Outcome {
    fn text(self) -> &'static str {
        match self {
            Outcome::Newer(_) => "newer",
            Outcome::Current(_) => "current",
            Outcome::Unavailable => "unavailable",
            Outcome::BundledUnknown => "bundled_version_unknown",
            Outcome::NotStored => "not_stored",
        }
    }
}

impl UpstreamCheck {
    /// The production check against `api.github.com`.
    #[cfg_attr(test, allow(dead_code))]
    pub fn live() -> Self {
        Self { mode: Mode::Live }
    }

    /// A check that asks `https://127.0.0.1:<port>`, trusting `root`.
    #[cfg(test)]
    pub fn local(port: u16, root: reqwest::Certificate) -> Self {
        Self {
            mode: Mode::Local {
                base: format!("https://127.0.0.1:{port}"),
                root,
            },
        }
    }

    fn client(&self) -> Option<(OutboundClient, &str)> {
        match &self.mode {
            Mode::Live => outbound::client(TargetClass::ScannerRelease, false)
                .ok()
                .map(|client| (client, GITHUB_BASE)),
            #[cfg(test)]
            Mode::Local { base, root } => {
                outbound::client_trusting(TargetClass::ScannerRelease, true, root.clone())
                    .ok()
                    .map(|client| (client, base.as_str()))
            }
        }
    }

    /// Checks both scanners once and records each answer. `bundled` holds the bundled Trivy
    /// and Grype versions. Never fails: each scanner's outcome is logged and returned.
    pub async fn check_once(
        &self,
        pool: &SqlitePool,
        bundled: [Option<Version>; 2],
        now: i64,
    ) -> [Outcome; 2] {
        let client = self.client();
        let mut outcomes = [Outcome::Unavailable; 2];
        for (slot, scanner) in SCANNERS.into_iter().enumerate() {
            let outcome = match &client {
                Some((http, base)) => {
                    check_scanner(pool, http, base, scanner, bundled[slot], now).await
                }
                None => Outcome::Unavailable,
            };
            match outcome {
                Outcome::Newer(latest) | Outcome::Current(latest) => tracing::info!(
                    scanner = scanner.key(),
                    outcome = outcome.text(),
                    latest_version = %latest.tagged(),
                    "scanner release check"
                ),
                _ => tracing::warn!(
                    scanner = scanner.key(),
                    outcome = outcome.text(),
                    "scanner release check"
                ),
            }
            outcomes[slot] = outcome;
        }
        outcomes
    }
}

async fn check_scanner(
    pool: &SqlitePool,
    http: &OutboundClient,
    base: &str,
    scanner: Scanner,
    bundled: Option<Version>,
    now: i64,
) -> Outcome {
    let url = format!("{base}/repos/{}/releases/latest", upstream_repo(scanner));
    let Some(latest) = fetch_latest(http, &url).await else {
        return Outcome::Unavailable;
    };
    let Some(bundled) = bundled else {
        return Outcome::BundledUnknown;
    };
    let newer = latest > bundled;
    let stored = scanner_releases::put(pool, scanner.key(), &latest.to_string(), newer, now).await;
    match (stored, newer) {
        (Err(_), _) => Outcome::NotStored,
        (Ok(()), true) => Outcome::Newer(latest),
        (Ok(()), false) => Outcome::Current(latest),
    }
}

/// One GET of the latest release. `None` for any failure, a draft, a pre-release, or a tag that
/// is not a plain version.
async fn fetch_latest(http: &OutboundClient, url: &str) -> Option<Version> {
    let url = reqwest::Url::parse(url).ok()?;
    let request = http.get(&url).ok()?;
    let mut response = request
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "Dockward")
        .header("x-github-api-version", "2022-11-28")
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await
        .ok()?;
    if response.status().as_u16() != 200 {
        return None;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if body.len() + chunk.len() > BODY_MAX_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    parse_release(&body)
}

/// The version of a stable release document. `None` for a draft, a pre-release, an unreadable
/// body or a tag that is not `vMAJOR.MINOR.PATCH`.
pub fn parse_release(body: &[u8]) -> Option<Version> {
    let release: Release = serde_json::from_slice(body).ok()?;
    if release.prerelease || release.draft {
        return None;
    }
    Version::parse(&release.tag_name)
}

/// Runs [`UpstreamCheck::check_once`] shortly after start and then once a day, until `stop`
/// turns true.
pub async fn run(
    pool: SqlitePool,
    check: UpstreamCheck,
    bundled: [Option<Version>; 2],
    mut stop: watch::Receiver<bool>,
) {
    let mut delay = FIRST_DELAY;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = stop.wait_for(|stopped| *stopped) => return,
        }
        tokio::select! {
            _ = check.check_once(&pool, bundled, now_secs()) => {}
            _ = stop.wait_for(|stopped| *stopped) => return,
        }
        delay = INTERVAL;
    }
}

#[cfg(test)]
mod tests;
