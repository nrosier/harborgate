//! Upstream check tests (#390). A loopback TLS server stands in for `api.github.com`: no test
//! reaches the real internet. The server records the request heads it receives.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::db;
use crate::services::outbound::socket_tests::loopback_tls_server_with;

const NOW: i64 = 1_800_000_000;
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn v(text: &str) -> Version {
    match Version::parse(text) {
        Some(version) => version,
        None => panic!("{text} should parse"),
    }
}

const BUNDLED: [Option<Version>; 2] = [
    Some(Version::from_parts(0, 76, 2)),
    Some(Version::from_parts(0, 121, 3)),
];

fn json(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn release(tag: &str, prerelease: bool) -> String {
    format!(r#"{{"tag_name":"{tag}","prerelease":{prerelease},"draft":false,"assets":[]}}"#)
}

struct Fx {
    pool: SqlitePool,
    dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn fx(name: &str) -> Fx {
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "dockward-upstream-{name}-{}-{seq}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(err) = std::fs::create_dir_all(&dir) {
        panic!("dir: {err}");
    }
    let pool = match db::open(&dir).await {
        Ok(pool) => pool,
        Err(err) => panic!("db: {err:?}"),
    };
    Fx { pool, dir }
}

/// Serves `trivy` and `grype` as the latest-release answers, and records every request head.
async fn serve(trivy: String, grype: String) -> (UpstreamCheck, Arc<Mutex<Vec<String>>>) {
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let record = Arc::clone(&seen);
    let (port, root) = loopback_tls_server_with(move |head| {
        if let Ok(mut seen) = record.lock() {
            seen.push(head.to_owned());
        }
        let target = head.split_whitespace().nth(1).unwrap_or_default();
        match target {
            "/repos/aquasecurity/trivy/releases/latest" => trivy.clone(),
            "/repos/anchore/grype/releases/latest" => grype.clone(),
            _ => json("404 Not Found", "{}"),
        }
    })
    .await;
    (UpstreamCheck::local(port, root), seen)
}

async fn row(pool: &SqlitePool, scanner: &str) -> Option<scanner_releases::ReleaseRow> {
    match scanner_releases::get(pool, scanner).await {
        Ok(row) => row,
        Err(err) => panic!("row: {err:?}"),
    }
}

#[test]
fn the_latest_tag_is_parsed() {
    assert_eq!(
        parse_release(release("v0.77.0", false).as_bytes()),
        Some(v("0.77.0"))
    );
    assert_eq!(
        parse_release(release("v0.122.0", false).as_bytes()),
        Some(v("0.122.0"))
    );
    // A pre-release, a draft, a malformed tag and an unreadable body are not answers.
    assert_eq!(parse_release(release("v0.78.0", true).as_bytes()), None);
    assert_eq!(
        parse_release(br#"{"tag_name":"v0.78.0","prerelease":false,"draft":true}"#),
        None
    );
    assert_eq!(
        parse_release(release("v0.78.0-rc1", false).as_bytes()),
        None
    );
    assert_eq!(parse_release(release("nightly", false).as_bytes()), None);
    assert_eq!(parse_release(b"not json"), None);
}

#[tokio::test]
async fn a_newer_release_is_recorded_and_an_equal_one_is_current() {
    let fx = fx("newer").await;
    let (check, seen) = serve(
        json("200 OK", &release("v0.77.0", false)),
        json("200 OK", &release("v0.121.3", false)),
    )
    .await;
    let outcomes = check.check_once(&fx.pool, BUNDLED, NOW).await;
    assert_eq!(
        outcomes,
        [Outcome::Newer(v("0.77.0")), Outcome::Current(v("0.121.3"))]
    );
    assert_eq!(
        row(&fx.pool, "trivy").await,
        Some(scanner_releases::ReleaseRow {
            scanner: "trivy".to_owned(),
            latest_version: "0.77.0".to_owned(),
            newer_than_bundled: true,
            checked_at: NOW,
        })
    );
    let grype = row(&fx.pool, "grype").await;
    assert_eq!(
        grype.map(|row| (row.latest_version, row.newer_than_bundled)),
        Some(("0.121.3".to_owned(), false))
    );
    // One GET per scanner, with no token or cookie.
    let heads = match seen.lock() {
        Ok(heads) => heads.clone(),
        Err(_) => panic!("lock"),
    };
    assert_eq!(heads.len(), 2);
    for head in &heads {
        assert!(head.starts_with("GET /repos/"), "{head}");
        let lower = head.to_ascii_lowercase();
        assert!(!lower.contains("authorization"), "{head}");
        assert!(!lower.contains("cookie"), "{head}");
    }
}

#[tokio::test]
async fn a_failed_check_records_nothing_and_keeps_the_last_answer() {
    let fx = fx("failed").await;
    let (check, _) = serve(
        json("200 OK", &release("v0.77.0", false)),
        json("200 OK", &release("v0.122.0", false)),
    )
    .await;
    check.check_once(&fx.pool, BUNDLED, NOW).await;

    // The next day: a server error, a pre-release, and nothing new is stored.
    let (check, _) = serve(
        json("503 Service Unavailable", "{}"),
        json("200 OK", &release("v0.123.0", true)),
    )
    .await;
    let outcomes = check.check_once(&fx.pool, BUNDLED, NOW + 86_400).await;
    assert_eq!(outcomes, [Outcome::Unavailable, Outcome::Unavailable]);
    let trivy = row(&fx.pool, "trivy").await;
    assert_eq!(
        trivy.map(|row| (row.latest_version, row.checked_at)),
        Some(("0.77.0".to_owned(), NOW))
    );
    let grype = row(&fx.pool, "grype").await;
    assert_eq!(
        grype.map(|row| (row.latest_version, row.checked_at)),
        Some(("0.122.0".to_owned(), NOW))
    );
}

#[tokio::test]
async fn an_unreachable_host_or_unknown_bundled_version_records_nothing() {
    let fx = fx("unreachable").await;
    // A port nothing listens on: the connection is refused.
    let (_, root) = loopback_tls_server_with(|_| String::new()).await;
    let check = UpstreamCheck::local(1, root);
    let outcomes = check.check_once(&fx.pool, BUNDLED, NOW).await;
    assert_eq!(outcomes, [Outcome::Unavailable, Outcome::Unavailable]);
    assert_eq!(row(&fx.pool, "trivy").await, None);
    assert_eq!(row(&fx.pool, "grype").await, None);

    let (check, _) = serve(
        json("200 OK", &release("v0.77.0", false)),
        json("200 OK", &release("v0.122.0", false)),
    )
    .await;
    let outcomes = check.check_once(&fx.pool, [None, None], NOW).await;
    assert_eq!(outcomes, [Outcome::BundledUnknown, Outcome::BundledUnknown]);
    assert_eq!(row(&fx.pool, "trivy").await, None);
}

/// The check never blocks a scan: it holds no scanner lock, so a scanner run that starts while a
/// check is stuck on a slow upstream finishes at once.
#[tokio::test]
async fn the_check_never_blocks_a_scan() {
    use crate::services::scan::ScanEnv;
    use crate::services::scanner::process::Limits;

    let fx = fx("noblock").await;
    // An upstream that never answers: the connection is queued by the kernel and never accepted,
    // so the TLS handshake waits.
    let silent = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(listener) => listener,
        Err(err) => panic!("bind: {err}"),
    };
    let port = match silent.local_addr() {
        Ok(addr) => addr.port(),
        Err(err) => panic!("addr: {err}"),
    };
    let (_, root) = loopback_tls_server_with(|_| String::new()).await;
    let check = UpstreamCheck::local(port, root);
    let pool = fx.pool.clone();
    let stuck = tokio::spawn(async move { check.check_once(&pool, BUNDLED, NOW).await });

    let bin = fx.dir.join("bin");
    if let Err(err) = std::fs::create_dir_all(&bin) {
        panic!("dir: {err}");
    }
    let script = bin.join("trivy");
    if let Err(err) = std::fs::write(&script, "#!/bin/sh\necho ok\n") {
        panic!("script: {err}");
    }
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) = std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        {
            panic!("chmod: {err}");
        }
    }
    let env = ScanEnv::with_programs(fx.dir.join("cache"), script.clone(), script);
    let started = std::time::Instant::now();
    let (result, _) = tokio::time::timeout(
        Duration::from_secs(5),
        env.run_scanner(Scanner::Trivy, &[], &[], Limits::default(), false),
    )
    .await
    .unwrap_or_else(|_| panic!("the scan waited for the check"));
    assert_eq!(result.ok(), Some(b"ok\n".to_vec()));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!stuck.is_finished(), "the check is still waiting upstream");
    stuck.abort();
    drop(silent);
}
