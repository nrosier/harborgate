//! Downloaded scanners on the data volume (#390, phase 1): the folder layout, the current and
//! previous pointers, the one-version rollback slot, the broken marker and the purge.
//!
//! Layout, under `<DOCKWARD_DATA_DIR>/scanners`:
//!
//! ```text
//! scanners/<scanner>/<version>/<scanner>   the binary of one downloaded version
//! scanners/<scanner>/<version>/broken      present when that version failed to launch
//! scanners/<scanner>/current               the version text of the version in use
//! scanners/<scanner>/previous              the version text of the one kept for rollback
//! ```
//!
//! `<scanner>` is the fixed key (`trivy`, `grype`) and `<version>` the canonical text of a
//! [`Version`] (`0.77.0`), so no upstream string ever reaches a path. A pointer is a small file
//! holding the version text; it is replaced by writing a temporary file and renaming it, so a
//! rollback is a pointer change and never moves a binary.
//!
//! Phase 1 places no binary here: downloading and verifying one is phase 2. This module holds no
//! database code and logs nothing; its callers log the scanner key and the version only.

use std::io::Write;
use std::path::{Path, PathBuf};

use super::Scanner;
use super::version::Version;
use crate::error::AppError;

/// The folder under the data directory that holds the downloaded scanners.
pub const SCANNERS_DIR: &str = "scanners";

/// The pointer to the version in use.
const CURRENT: &str = "current";
/// The pointer to the version kept for rollback.
const PREVIOUS: &str = "previous";
/// The marker of a version that failed to launch.
const BROKEN: &str = "broken";
/// The longest pointer file that is read. A valid one is far shorter.
const MAX_POINTER_BYTES: u64 = 64;

/// One of the two pointers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    Current,
    Previous,
}

impl Slot {
    fn file_name(self) -> &'static str {
        match self {
            Slot::Current => CURRENT,
            Slot::Previous => PREVIOUS,
        }
    }
}

/// A pointer as read from disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pointer {
    /// No pointer file.
    Absent,
    /// A pointer file that does not hold a valid version (or could not be read).
    Malformed,
    /// A valid version.
    Version(Version),
}

impl Pointer {
    pub fn version(self) -> Option<Version> {
        match self {
            Pointer::Version(version) => Some(version),
            Pointer::Absent | Pointer::Malformed => None,
        }
    }
}

/// The downloaded scanners under one data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerVolume {
    root: PathBuf,
}

fn io_err<E>(_: E) -> AppError {
    AppError::InternalError
}

impl ScannerVolume {
    /// The volume under `<data dir>/scanners`.
    pub fn under(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join(SCANNERS_DIR),
        }
    }

    /// `scanners/<scanner>`.
    pub fn scanner_dir(&self, scanner: Scanner) -> PathBuf {
        self.root.join(scanner.key())
    }

    /// `scanners/<scanner>/<version>`.
    pub fn version_dir(&self, scanner: Scanner, version: Version) -> PathBuf {
        self.scanner_dir(scanner).join(version.to_string())
    }

    /// `scanners/<scanner>/<version>/<scanner>`: where the binary of a downloaded version lives.
    pub fn binary_path(&self, scanner: Scanner, version: Version) -> PathBuf {
        self.version_dir(scanner, version).join(scanner.key())
    }

    /// True when the binary of `version` is a regular file.
    pub fn has_binary(&self, scanner: Scanner, version: Version) -> bool {
        self.binary_path(scanner, version).is_file()
    }

    /// True when anything was ever downloaded for `scanner` (its folder exists).
    pub fn exists(&self, scanner: Scanner) -> bool {
        self.scanner_dir(scanner).exists()
    }

    /// Reads one pointer. A file that is too long, unreadable or not a valid version is
    /// [`Pointer::Malformed`].
    pub fn read(&self, scanner: Scanner, slot: Slot) -> Pointer {
        let path = self.scanner_dir(scanner).join(slot.file_name());
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Pointer::Absent,
            Err(_) => return Pointer::Malformed,
        };
        if !meta.is_file() || meta.len() > MAX_POINTER_BYTES {
            return Pointer::Malformed;
        }
        match std::fs::read_to_string(&path) {
            Ok(text) => Version::parse(text.trim())
                .map(Pointer::Version)
                .unwrap_or(Pointer::Malformed),
            Err(_) => Pointer::Malformed,
        }
    }

    /// Points `slot` at `version`: a temporary file, then a rename over the pointer.
    fn write(&self, scanner: Scanner, slot: Slot, version: Version) -> Result<(), AppError> {
        let dir = self.scanner_dir(scanner);
        std::fs::create_dir_all(&dir).map_err(io_err)?;
        let target = dir.join(slot.file_name());
        let temp = dir.join(format!(".{}.tmp", slot.file_name()));
        let mut file = std::fs::File::create(&temp).map_err(io_err)?;
        file.write_all(format!("{version}\n").as_bytes())
            .map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
        drop(file);
        std::fs::rename(&temp, &target).map_err(io_err)
    }

    /// Records `version` as the version in use and keeps the old one as the previous version,
    /// so a later [`Self::rollback`] returns to it. A further update replaces the previous one:
    /// the folder of the version that drops out of both pointers is deleted. The binary of
    /// `version` must already be in place. Recording the version already in use changes nothing.
    // Phase 2 (download and verification, #390) installs a version through this.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn record_current(&self, scanner: Scanner, version: Version) -> Result<(), AppError> {
        if !self.has_binary(scanner, version) {
            return Err(AppError::NotFound);
        }
        let old_current = self.read(scanner, Slot::Current).version();
        if old_current == Some(version) {
            return Ok(());
        }
        let old_previous = self.read(scanner, Slot::Previous).version();
        if let Some(current) = old_current {
            self.write(scanner, Slot::Previous, current)?;
        }
        self.write(scanner, Slot::Current, version)?;
        if let Some(dropped) = old_previous
            && Some(dropped) != old_current
            && dropped != version
        {
            self.remove_version(scanner, dropped)?;
        }
        Ok(())
    }

    /// Switches the current pointer to the previous version, and the old current one becomes the
    /// previous one, so a second rollback goes back. Returns the version now in use.
    /// [`AppError::NotFound`] when no previous version with a binary is kept.
    // Phase 2 and the UI phase (#390) expose this as an admin action.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn rollback(&self, scanner: Scanner) -> Result<Version, AppError> {
        let Some(previous) = self.read(scanner, Slot::Previous).version() else {
            return Err(AppError::NotFound);
        };
        if !self.has_binary(scanner, previous) {
            return Err(AppError::NotFound);
        }
        let current = self.read(scanner, Slot::Current).version();
        self.write(scanner, Slot::Current, previous)?;
        match current {
            Some(current) if current != previous => {
                self.write(scanner, Slot::Previous, current)?;
            }
            _ => self.clear(scanner, Slot::Previous)?,
        }
        Ok(previous)
    }

    /// Removes a pointer. A missing pointer is fine.
    #[cfg_attr(not(test), allow(dead_code))]
    fn clear(&self, scanner: Scanner, slot: Slot) -> Result<(), AppError> {
        match std::fs::remove_file(self.scanner_dir(scanner).join(slot.file_name())) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(io_err(err)),
        }
    }

    /// Deletes the folder of one version. A missing folder is fine.
    #[cfg_attr(not(test), allow(dead_code))]
    fn remove_version(&self, scanner: Scanner, version: Version) -> Result<(), AppError> {
        remove_dir(&self.version_dir(scanner, version))
    }

    /// Marks `version` broken: it failed to launch. The marker survives a restart, so the
    /// version is not selected again.
    pub fn mark_broken(&self, scanner: Scanner, version: Version) -> Result<(), AppError> {
        let dir = self.version_dir(scanner, version);
        std::fs::create_dir_all(&dir).map_err(io_err)?;
        std::fs::write(dir.join(BROKEN), b"launch failed\n").map_err(io_err)
    }

    /// True when `version` carries the broken marker.
    pub fn is_broken(&self, scanner: Scanner, version: Version) -> bool {
        self.version_dir(scanner, version).join(BROKEN).exists()
    }

    /// Deletes everything downloaded for `scanner`: every version folder and both pointers.
    pub fn purge(&self, scanner: Scanner) -> Result<(), AppError> {
        remove_dir(&self.scanner_dir(scanner))
    }
}

fn remove_dir(path: &Path) -> Result<(), AppError> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(io_err(err)),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A fresh, empty data directory.
    pub(crate) fn temp_data_dir(name: &str) -> PathBuf {
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "dockward-volume-{name}-{}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(err) = std::fs::create_dir_all(&dir) {
            panic!("dir: {err}");
        }
        dir
    }

    pub(crate) fn v(text: &str) -> Version {
        match Version::parse(text) {
            Some(version) => version,
            None => panic!("{text} should parse"),
        }
    }

    /// Places a binary file for `version` (its content is never run by these tests).
    pub(crate) fn place(volume: &ScannerVolume, scanner: Scanner, version: Version, body: &str) {
        let dir = volume.version_dir(scanner, version);
        if let Err(err) = std::fs::create_dir_all(&dir) {
            panic!("dir: {err}");
        }
        if let Err(err) = std::fs::write(volume.binary_path(scanner, version), body) {
            panic!("binary: {err}");
        }
    }

    fn pointers(volume: &ScannerVolume) -> (Option<Version>, Option<Version>) {
        (
            volume.read(Scanner::Trivy, Slot::Current).version(),
            volume.read(Scanner::Trivy, Slot::Previous).version(),
        )
    }

    #[test]
    fn the_layout_is_versioned_folders_under_the_data_volume() {
        let volume = ScannerVolume::under(Path::new("/data"));
        assert_eq!(
            volume.binary_path(Scanner::Trivy, v("0.77.0")),
            PathBuf::from("/data/scanners/trivy/0.77.0/trivy")
        );
        assert_eq!(
            volume.binary_path(Scanner::Grype, v("v0.122.0")),
            PathBuf::from("/data/scanners/grype/0.122.0/grype")
        );
    }

    #[test]
    fn a_new_current_keeps_the_old_one_as_previous() {
        let dir = temp_data_dir("record");
        let volume = ScannerVolume::under(&dir);
        place(&volume, Scanner::Trivy, v("0.77.0"), "a");
        volume
            .record_current(Scanner::Trivy, v("0.77.0"))
            .expect_test_ok();
        assert_eq!(pointers(&volume), (Some(v("0.77.0")), None));
        place(&volume, Scanner::Trivy, v("0.78.0"), "b");
        volume
            .record_current(Scanner::Trivy, v("0.78.0"))
            .expect_test_ok();
        assert_eq!(pointers(&volume), (Some(v("0.78.0")), Some(v("0.77.0"))));
        // Recording the version in use again changes nothing.
        volume
            .record_current(Scanner::Trivy, v("0.78.0"))
            .expect_test_ok();
        assert_eq!(pointers(&volume), (Some(v("0.78.0")), Some(v("0.77.0"))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_update_replaces_the_previous_version() {
        let dir = temp_data_dir("replace");
        let volume = ScannerVolume::under(&dir);
        for version in ["0.77.0", "0.78.0", "0.79.0"] {
            place(&volume, Scanner::Trivy, v(version), version);
            volume
                .record_current(Scanner::Trivy, v(version))
                .expect_test_ok();
        }
        assert_eq!(pointers(&volume), (Some(v("0.79.0")), Some(v("0.78.0"))));
        // Exactly one previous version is kept: the oldest folder is gone.
        assert!(!volume.version_dir(Scanner::Trivy, v("0.77.0")).exists());
        assert!(volume.has_binary(Scanner::Trivy, v("0.78.0")));
        assert!(volume.has_binary(Scanner::Trivy, v("0.79.0")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rollback_swaps_current_and_previous() {
        let dir = temp_data_dir("rollback");
        let volume = ScannerVolume::under(&dir);
        for version in ["0.77.0", "0.78.0"] {
            place(&volume, Scanner::Trivy, v(version), version);
            volume
                .record_current(Scanner::Trivy, v(version))
                .expect_test_ok();
        }
        assert_eq!(
            volume.rollback(Scanner::Trivy).expect_test_ok(),
            v("0.77.0")
        );
        assert_eq!(pointers(&volume), (Some(v("0.77.0")), Some(v("0.78.0"))));
        // A second rollback goes back; no binary moved.
        assert_eq!(
            volume.rollback(Scanner::Trivy).expect_test_ok(),
            v("0.78.0")
        );
        assert_eq!(pointers(&volume), (Some(v("0.78.0")), Some(v("0.77.0"))));
        assert!(volume.has_binary(Scanner::Trivy, v("0.77.0")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rollback_without_a_previous_version_is_refused() {
        let dir = temp_data_dir("no-previous");
        let volume = ScannerVolume::under(&dir);
        assert!(matches!(
            volume.rollback(Scanner::Trivy),
            Err(AppError::NotFound)
        ));
        place(&volume, Scanner::Trivy, v("0.77.0"), "a");
        volume
            .record_current(Scanner::Trivy, v("0.77.0"))
            .expect_test_ok();
        assert!(matches!(
            volume.rollback(Scanner::Trivy),
            Err(AppError::NotFound)
        ));
        assert_eq!(pointers(&volume), (Some(v("0.77.0")), None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_version_without_a_binary_is_not_recorded() {
        let dir = temp_data_dir("no-binary");
        let volume = ScannerVolume::under(&dir);
        assert!(matches!(
            volume.record_current(Scanner::Trivy, v("0.77.0")),
            Err(AppError::NotFound)
        ));
        assert_eq!(pointers(&volume), (None, None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_pointer_is_not_a_version() {
        let dir = temp_data_dir("malformed");
        let volume = ScannerVolume::under(&dir);
        assert_eq!(volume.read(Scanner::Trivy, Slot::Current), Pointer::Absent);
        let scanner_dir = volume.scanner_dir(Scanner::Trivy);
        if let Err(err) = std::fs::create_dir_all(&scanner_dir) {
            panic!("dir: {err}");
        }
        for text in ["0.77", "../../etc", "0.77.0-rc1", &"9".repeat(100)] {
            if let Err(err) = std::fs::write(scanner_dir.join(CURRENT), text) {
                panic!("pointer: {err}");
            }
            assert_eq!(
                volume.read(Scanner::Trivy, Slot::Current),
                Pointer::Malformed,
                "{text:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_broken_marker_and_the_purge() {
        let dir = temp_data_dir("broken");
        let volume = ScannerVolume::under(&dir);
        place(&volume, Scanner::Grype, v("0.122.0"), "a");
        assert!(!volume.is_broken(Scanner::Grype, v("0.122.0")));
        volume
            .mark_broken(Scanner::Grype, v("0.122.0"))
            .expect_test_ok();
        assert!(volume.is_broken(Scanner::Grype, v("0.122.0")));
        volume.purge(Scanner::Grype).expect_test_ok();
        assert!(!volume.exists(Scanner::Grype));
        // Purging nothing is fine.
        volume.purge(Scanner::Grype).expect_test_ok();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `Result::expect` without the lint: panics with the error.
    pub(crate) trait ExpectTestOk<T> {
        fn expect_test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> ExpectTestOk<T> for Result<T, E> {
        fn expect_test_ok(self) -> T {
            match self {
                Ok(value) => value,
                Err(err) => panic!("unexpected error: {err:?}"),
            }
        }
    }
}
