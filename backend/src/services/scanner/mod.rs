//! Trivy and Grype: the verified command lines, the environment allow-list, the strict readers
//! and the daily database refresh (`specs/spinoff-local-scan.md`, sections 7 and 8; decisions 4,
//! 5, 19, 28, 29 and 30).
//!
//! The executables are pinned and copied into the scratch app image, and are called by absolute
//! path. The only variable argument is the OCI layout directory, which is generated from an id by
//! the caller. No registry, repository or tag string reaches an argument, a file name or the
//! environment.
//!
//! Submodules: [`process`] runs a child process, [`parse`] reads the JSON, [`db_refresh`] runs
//! the daily refresh, [`volume`] and [`selection`] pick the bundled or a downloaded binary
//! (#390), [`upstream_check`] asks GitHub daily for the latest stable release. This module holds
//! the command lines. It has no database code.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub mod db_refresh;
pub mod db_update;
pub mod parse;
pub mod process;
pub mod redact;
pub mod selection;
pub mod steplog;
pub mod upstream_check;
pub mod version;
pub mod volume;

/// The two scanners. Their keys are fixed (the `scanner` column of `scan_runs` and
/// `scanner_databases`, `specs/spinoff-local-scan.md`, section 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scanner {
    Trivy,
    Grype,
}

impl Scanner {
    /// The fixed key stored in `scanner_databases.scanner` and `scan_runs.scanner`.
    pub fn key(self) -> &'static str {
        match self {
            Scanner::Trivy => "trivy",
            Scanner::Grype => "grype",
        }
    }

    /// The absolute path of the pinned executable in the app image (decision 23). It is the
    /// default; the binary a run uses is resolved by [`selection::program_for`], which returns
    /// this path unless a newer downloaded version is selected (#390).
    pub fn bundled_program(self) -> &'static Path {
        match self {
            Scanner::Trivy => Path::new("/usr/local/bin/trivy"),
            Scanner::Grype => Path::new("/usr/local/bin/grype"),
        }
    }
}

/// The directory a scanner uses for its database, under the scanner cache root.
pub fn cache_dir(cache_root: &Path, scanner: Scanner) -> PathBuf {
    cache_root.join(scanner.key())
}

/// The temp directory for a scanner's child process (`TMPDIR`). It sits under the scanner's own
/// cache, on the data volume, because `/tmp` may be a small tmpfs.
pub fn temp_dir(cache_root: &Path, scanner: Scanner) -> PathBuf {
    cache_dir(cache_root, scanner).join("tmp")
}

/// The argument vector of a scan run for `layout_dir`, the directory generated from an id.
///
/// Trivy: `image --input <dir> --format json --skip-db-update --skip-java-db-update`, the output
/// on stdout. The verified call of decision 28 and 29.
///
/// Grype: `oci-dir:<dir> -o json`, the output on stdout. Grype has no `--db-auto-update` flag;
/// the database download is switched off by an environment variable (decision 29), not here.
pub fn scan_args(scanner: Scanner, layout_dir: &Path) -> Vec<OsString> {
    match scanner {
        Scanner::Trivy => vec![
            "image".into(),
            "--input".into(),
            layout_dir.as_os_str().to_owned(),
            "--format".into(),
            "json".into(),
            "--skip-db-update".into(),
            "--skip-java-db-update".into(),
        ],
        Scanner::Grype => {
            let mut source = OsString::from("oci-dir:");
            source.push(layout_dir.as_os_str());
            vec![source, "-o".into(), "json".into()]
        }
    }
}

/// The argument vector of the database download for `scanner` (decision 28 and 29).
///
/// Trivy: `image --download-db-only` and `--download-java-db-only`. Grype: `db update`. Both
/// print nothing that is stored.
pub fn update_args(scanner: Scanner) -> Vec<Vec<OsString>> {
    match scanner {
        Scanner::Trivy => vec![
            vec!["image".into(), "--download-db-only".into()],
            vec!["image".into(), "--download-java-db-only".into()],
        ],
        Scanner::Grype => vec![vec!["db".into(), "update".into()]],
    }
}

/// The environment allow-list for a scanner run or update (section 7). Only the cache location,
/// the offline settings and the home directory are set. No secret is ever added here, and
/// `DOCKWARD_ENCRYPTION_KEY` and the old key are never read.
///
/// `scan` is `true` for a scan run: its database download is off. An update run leaves the
/// downloads on, so the database can be fetched.
pub fn environment(cache_root: &Path, scanner: Scanner, scan: bool) -> Vec<(OsString, OsString)> {
    let cache = cache_dir(cache_root, scanner);
    let home = cache_root.to_owned();
    let tmp = temp_dir(cache_root, scanner);
    let mut env: Vec<(OsString, OsString)> = vec![
        ("HOME".into(), home.as_os_str().to_owned()),
        ("LC_ALL".into(), "C.UTF-8".into()),
        ("TMPDIR".into(), tmp.as_os_str().to_owned()),
    ];
    match scanner {
        Scanner::Trivy => {
            env.push(("TRIVY_CACHE_DIR".into(), cache.as_os_str().to_owned()));
            env.push(("TRIVY_DISABLE_TELEMETRY".into(), "true".into()));
            env.push(("TRIVY_SKIP_VERSION_CHECK".into(), "true".into()));
        }
        Scanner::Grype => {
            env.push(("GRYPE_DB_CACHE_DIR".into(), cache.as_os_str().to_owned()));
            env.push(("GRYPE_CHECK_FOR_APP_UPDATE".into(), "false".into()));
            if scan {
                env.push(("GRYPE_DB_AUTO_UPDATE".into(), "false".into()));
            }
        }
    }
    env
}

#[cfg(test)]
mod mod_tests;
