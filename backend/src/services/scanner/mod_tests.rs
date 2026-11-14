use std::path::Path;

use super::*;

fn env_names(env: &[(OsString, OsString)]) -> Vec<String> {
    env.iter()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn trivy_scan_call_matches_the_verified_form() {
    let args = scan_args(Scanner::Trivy, Path::new("/data/images/.tmp/abc"));
    let text: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        text,
        vec![
            "image",
            "--input",
            "/data/images/.tmp/abc",
            "--format",
            "json",
            "--skip-db-update",
            "--skip-java-db-update",
        ]
    );
}

#[test]
fn grype_scan_call_uses_oci_dir_and_no_update_flag() {
    let args = scan_args(Scanner::Grype, Path::new("/data/images/abc"));
    let text: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert_eq!(text, vec!["oci-dir:/data/images/abc", "-o", "json"]);
    assert!(
        !text.iter().any(|a| a.contains("db-auto-update")),
        "Grype has no such flag; the setting is the environment variable"
    );
}

#[test]
fn programs_are_absolute_paths() {
    assert!(Scanner::Trivy.bundled_program().is_absolute());
    assert!(Scanner::Grype.bundled_program().is_absolute());
}

#[test]
fn update_calls_fetch_each_database() {
    let trivy = update_args(Scanner::Trivy);
    assert_eq!(trivy.len(), 2);
    assert!(trivy[0].iter().any(|a| a == "--download-db-only"));
    assert!(trivy[1].iter().any(|a| a == "--download-java-db-only"));
    let grype = update_args(Scanner::Grype);
    assert_eq!(grype.len(), 1);
    assert_eq!(grype[0][0], "db");
    assert_eq!(grype[0][1], "update");
}

#[test]
fn scan_environment_disables_grype_downloads_and_holds_no_secret() {
    let root = Path::new("/data/scanner-cache");
    let env = environment(root, Scanner::Grype, true);
    let names = env_names(&env);
    assert!(names.iter().any(|n| n == "GRYPE_DB_AUTO_UPDATE"));
    assert!(names.iter().any(|n| n == "GRYPE_DB_CACHE_DIR"));
    for name in &names {
        assert!(!name.contains("ENCRYPTION_KEY"), "{name}");
        assert!(!name.contains("SECRET"), "{name}");
        assert!(!name.contains("TOKEN"), "{name}");
    }
    let values: Vec<String> = env
        .iter()
        .map(|(_, v)| v.to_string_lossy().into_owned())
        .collect();
    assert!(values.iter().any(|v| v == "/data/scanner-cache/grype"));
}

#[test]
fn update_environment_keeps_grype_downloads_on() {
    let root = Path::new("/data/scanner-cache");
    let env = environment(root, Scanner::Grype, false);
    assert!(!env_names(&env).iter().any(|n| n == "GRYPE_DB_AUTO_UPDATE"));
}

#[test]
fn trivy_environment_points_at_its_cache() {
    let root = Path::new("/data/scanner-cache");
    let env = environment(root, Scanner::Trivy, true);
    let cache = env
        .iter()
        .find(|(name, _)| name == "TRIVY_CACHE_DIR")
        .map(|(_, value)| value.to_string_lossy().into_owned());
    assert_eq!(cache.as_deref(), Some("/data/scanner-cache/trivy"));
}

/// Regression: without a HOME, Trivy falls back to `/` and fails with `mkdir /.cache: permission
/// denied`. The child environment must always carry a HOME inside the cache root, for both scanners.
#[test]
fn scanner_environments_always_set_a_home_inside_the_cache_root() {
    let root = Path::new("/data/scanner-cache");
    for scanner in [Scanner::Trivy, Scanner::Grype] {
        for scan in [true, false] {
            let env = environment(root, scanner, scan);
            let home = env
                .iter()
                .find(|(name, _)| name == "HOME")
                .map(|(_, value)| value.to_string_lossy().into_owned());
            assert_eq!(
                home.as_deref(),
                Some("/data/scanner-cache"),
                "{scanner:?} scan={scan}"
            );
        }
    }
}

/// Regression: the scanner child runs with a cleared environment, so without TMPDIR Grype and
/// Trivy write temp files to `/tmp`, which is a 64 MB tmpfs in the compose file, and the database
/// download fails with "no space left on device". TMPDIR must point inside the cache root.
#[test]
fn scanner_environments_point_tmpdir_inside_the_cache_root() {
    let root = Path::new("/data/scanner-cache");
    for scanner in [Scanner::Trivy, Scanner::Grype] {
        for scan in [true, false] {
            let env = environment(root, scanner, scan);
            let tmp = env
                .iter()
                .find(|(name, _)| name == "TMPDIR")
                .map(|(_, value)| std::path::PathBuf::from(value));
            let tmp = tmp.unwrap_or_else(|| panic!("{scanner:?} scan={scan}: TMPDIR is not set"));
            assert!(
                tmp.starts_with(root) && tmp != root,
                "{scanner:?} scan={scan}: TMPDIR {tmp:?} is not inside {root:?}"
            );
        }
    }
}
