//! Which scanner binary runs (#390, phase 1): the bundled one in the image, or a downloaded one
//! on the data volume ([`super::volume`]).
//!
//! The bundled scanners stay the default, so dockward works offline and starts with nothing
//! downloaded. At startup, per scanner ([`select`]):
//!
//! - nothing downloaded: the bundled binary;
//! - a downloaded version newer than the bundled one (numerically per component, `0.76.10` >
//!   `0.76.9`): the downloaded binary;
//! - a downloaded version equal to or older than the bundled one: the downloaded folder is purged
//!   and the bundled binary is used;
//! - a malformed downloaded version: treated as not newer, so it is purged and never used;
//! - a downloaded version marked broken, or with no binary, or a bundled version that could not
//!   be read: the bundled binary, and nothing is deleted.
//!
//! At scan time a downloaded binary that does not start (the spawn fails) is marked broken and
//! the bundled binary takes over ([`ScannerPrograms::launch_failed`]); the scan runs again with
//! it. A normal non-zero exit of a scan is not a launch failure. The broken state is kept on disk
//! and exposed by [`ScannerPrograms::state`].
//!
//! Logs hold the scanner key, the decision and version numbers only, never a path.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::Scanner;
use super::version::Version;
use super::volume::{Pointer, ScannerVolume, Slot};

/// The binary a scanner runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selected {
    /// The pinned binary in the image.
    Bundled,
    /// A downloaded version on the data volume.
    Downloaded(Version),
}

/// What the startup selection decided, for the log and the tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// No downloaded version exists.
    NothingDownloaded,
    /// The downloaded version is newer than the bundled one and is used.
    UseDownloaded(Version),
    /// The downloaded version is not newer than the bundled one: purged.
    PurgedNotNewer(Version),
    /// The downloaded version is malformed: purged.
    PurgedMalformed,
    /// The bundled version could not be read, so no comparison is possible. Nothing is deleted.
    BundledUnknown,
    /// The downloaded version is marked broken. Nothing is deleted.
    Broken(Version),
    /// The downloaded version has no binary. Nothing is deleted.
    MissingBinary(Version),
}

impl Decision {
    fn text(self) -> &'static str {
        match self {
            Decision::NothingDownloaded => "nothing_downloaded",
            Decision::UseDownloaded(_) => "use_downloaded",
            Decision::PurgedNotNewer(_) => "purged_not_newer",
            Decision::PurgedMalformed => "purged_malformed",
            Decision::BundledUnknown => "bundled_version_unknown",
            Decision::Broken(_) => "downloaded_broken",
            Decision::MissingBinary(_) => "downloaded_missing_binary",
        }
    }

    fn version(self) -> Option<Version> {
        match self {
            Decision::UseDownloaded(v)
            | Decision::PurgedNotNewer(v)
            | Decision::Broken(v)
            | Decision::MissingBinary(v) => Some(v),
            Decision::NothingDownloaded | Decision::PurgedMalformed | Decision::BundledUnknown => {
                None
            }
        }
    }
}

/// The selection of one scanner: what runs, and a downloaded version known to be broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannerState {
    pub selected: Selected,
    pub broken: Option<Version>,
}

impl ScannerState {
    const BUNDLED: Self = Self {
        selected: Selected::Bundled,
        broken: None,
    };
}

/// Applies the startup rule for one scanner. `bundled` is the bundled version, `None` when it
/// could not be read. A purge that fails is logged and the bundled binary is used anyway.
pub fn select(
    volume: &ScannerVolume,
    scanner: Scanner,
    bundled: Option<Version>,
) -> (ScannerState, Decision) {
    if !volume.exists(scanner) {
        return (ScannerState::BUNDLED, Decision::NothingDownloaded);
    }
    let downloaded = match volume.read(scanner, Slot::Current) {
        Pointer::Absent => return (ScannerState::BUNDLED, Decision::NothingDownloaded),
        Pointer::Malformed => {
            purge(volume, scanner);
            return (ScannerState::BUNDLED, Decision::PurgedMalformed);
        }
        Pointer::Version(version) => version,
    };
    let Some(bundled) = bundled else {
        return (ScannerState::BUNDLED, Decision::BundledUnknown);
    };
    if downloaded <= bundled {
        purge(volume, scanner);
        return (ScannerState::BUNDLED, Decision::PurgedNotNewer(downloaded));
    }
    if volume.is_broken(scanner, downloaded) {
        let state = ScannerState {
            selected: Selected::Bundled,
            broken: Some(downloaded),
        };
        return (state, Decision::Broken(downloaded));
    }
    if !volume.has_binary(scanner, downloaded) {
        return (ScannerState::BUNDLED, Decision::MissingBinary(downloaded));
    }
    let state = ScannerState {
        selected: Selected::Downloaded(downloaded),
        broken: None,
    };
    (state, Decision::UseDownloaded(downloaded))
}

fn purge(volume: &ScannerVolume, scanner: Scanner) {
    if volume.purge(scanner).is_err() {
        tracing::warn!(
            scanner = scanner.key(),
            "the downloaded scanner could not be purged"
        );
    }
}

/// The path of the binary for `selected`: the bundled path, or the downloaded binary on the
/// volume. The one place a scanner's program path is resolved.
pub fn program_for(
    selected: Selected,
    scanner: Scanner,
    volume: &ScannerVolume,
    bundled: &Path,
) -> PathBuf {
    match selected {
        Selected::Bundled => bundled.to_owned(),
        Selected::Downloaded(version) => volume.binary_path(scanner, version),
    }
}

/// The live selection of both scanners. Shared by the scan job, the database refresh and the
/// About route. The lock is never held across an await.
#[derive(Debug)]
pub struct ScannerPrograms {
    volume: ScannerVolume,
    bundled_trivy: PathBuf,
    bundled_grype: PathBuf,
    state: Mutex<[ScannerState; 2]>,
}

fn index(scanner: Scanner) -> usize {
    match scanner {
        Scanner::Trivy => 0,
        Scanner::Grype => 1,
    }
}

impl ScannerPrograms {
    /// Both scanners on their bundled binaries. Nothing on the volume is read or changed.
    pub fn bundled(data_dir: &Path) -> Self {
        Self::with_bundled_paths(
            data_dir,
            Scanner::Trivy.bundled_program().to_owned(),
            Scanner::Grype.bundled_program().to_owned(),
        )
    }

    /// Like [`Self::bundled`] with other bundled paths. Used by the tests, with scripts.
    pub fn with_bundled_paths(data_dir: &Path, trivy: PathBuf, grype: PathBuf) -> Self {
        Self {
            volume: ScannerVolume::under(data_dir),
            bundled_trivy: trivy,
            bundled_grype: grype,
            state: Mutex::new([ScannerState::BUNDLED; 2]),
        }
    }

    /// Applies the startup rule ([`select`]) to both scanners and logs each decision.
    /// `bundled` holds the bundled Trivy and Grype versions.
    pub fn select_at_startup(self, bundled: [Option<Version>; 2]) -> Self {
        let mut states = [ScannerState::BUNDLED; 2];
        for scanner in [Scanner::Trivy, Scanner::Grype] {
            let (state, decision) = select(&self.volume, scanner, bundled[index(scanner)]);
            let version = decision.version().map(|v| v.tagged());
            tracing::info!(
                scanner = scanner.key(),
                decision = decision.text(),
                downloaded_version = version.as_deref().unwrap_or("none"),
                "scanner selected"
            );
            states[index(scanner)] = state;
        }
        *self.lock() = states;
        self
    }

    fn lock(&self) -> MutexGuard<'_, [ScannerState; 2]> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn bundled_path(&self, scanner: Scanner) -> &Path {
        match scanner {
            Scanner::Trivy => &self.bundled_trivy,
            Scanner::Grype => &self.bundled_grype,
        }
    }

    /// The selection of `scanner` now.
    pub fn state(&self, scanner: Scanner) -> ScannerState {
        self.lock()[index(scanner)]
    }

    /// The binary to run for `scanner` now, and the selection it came from. Pass the selection
    /// to [`Self::launch_failed`] when the binary does not start.
    pub fn program(&self, scanner: Scanner) -> (PathBuf, Selected) {
        let selected = self.state(scanner).selected;
        let path = program_for(selected, scanner, &self.volume, self.bundled_path(scanner));
        (path, selected)
    }

    /// Reports that the binary of `used` did not start. For a downloaded version: marks it
    /// broken (on disk, so a restart does not pick it again), switches `scanner` to the bundled
    /// binary, and returns `true` so the caller runs again with it. For the bundled binary
    /// there is nothing to fall back to: returns `false`.
    pub fn launch_failed(&self, scanner: Scanner, used: Selected) -> bool {
        let Selected::Downloaded(version) = used else {
            return false;
        };
        {
            let mut states = self.lock();
            let state = &mut states[index(scanner)];
            if state.selected == used {
                state.selected = Selected::Bundled;
            }
            state.broken = Some(version);
        }
        if self.volume.mark_broken(scanner, version).is_err() {
            tracing::warn!(
                scanner = scanner.key(),
                "the broken marker of a downloaded scanner could not be written"
            );
        }
        tracing::warn!(
            scanner = scanner.key(),
            downloaded_version = %version.tagged(),
            outcome = "launch_failed",
            "the downloaded scanner did not start; the bundled scanner is used"
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::scanner::volume::tests::{ExpectTestOk, place, temp_data_dir, v};

    fn setup(name: &str, current: &str) -> (PathBuf, ScannerVolume) {
        let dir = temp_data_dir(name);
        let volume = ScannerVolume::under(&dir);
        place(&volume, Scanner::Trivy, v(current), "bin");
        volume
            .record_current(Scanner::Trivy, v(current))
            .expect_test_ok();
        (dir, volume)
    }

    #[test]
    fn nothing_downloaded_uses_the_bundled_binary() {
        let dir = temp_data_dir("sel-none");
        let volume = ScannerVolume::under(&dir);
        let (state, decision) = select(&volume, Scanner::Trivy, Some(v("0.76.2")));
        assert_eq!(state, ScannerState::BUNDLED);
        assert_eq!(decision, Decision::NothingDownloaded);
        let programs = ScannerPrograms::bundled(&dir).select_at_startup([Some(v("0.76.2")); 2]);
        assert_eq!(
            programs.program(Scanner::Trivy),
            (PathBuf::from("/usr/local/bin/trivy"), Selected::Bundled)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_newer_downloaded_version_is_used() {
        // 0.76.10 is newer than 0.76.9: the comparison is numeric per component.
        let (dir, volume) = setup("sel-newer", "0.76.10");
        let (state, decision) = select(&volume, Scanner::Trivy, Some(v("0.76.9")));
        assert_eq!(state.selected, Selected::Downloaded(v("0.76.10")));
        assert_eq!(decision, Decision::UseDownloaded(v("0.76.10")));
        let programs = ScannerPrograms::bundled(&dir).select_at_startup([Some(v("0.76.9")), None]);
        assert_eq!(
            programs.program(Scanner::Trivy).0,
            dir.join("scanners/trivy/0.76.10/trivy")
        );
        // Grype has nothing downloaded and stays bundled.
        assert_eq!(programs.program(Scanner::Grype).1, Selected::Bundled);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_equal_downloaded_version_is_purged_and_the_bundled_one_used() {
        let (dir, volume) = setup("sel-equal", "0.76.2");
        let (state, decision) = select(&volume, Scanner::Trivy, Some(v("0.76.2")));
        assert_eq!(state, ScannerState::BUNDLED);
        assert_eq!(decision, Decision::PurgedNotNewer(v("0.76.2")));
        assert!(!volume.exists(Scanner::Trivy), "the download is purged");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_older_downloaded_version_is_purged_and_the_bundled_one_used() {
        let (dir, volume) = setup("sel-older", "0.76.9");
        let (state, decision) = select(&volume, Scanner::Trivy, Some(v("0.76.10")));
        assert_eq!(state, ScannerState::BUNDLED);
        assert_eq!(decision, Decision::PurgedNotNewer(v("0.76.9")));
        assert!(!volume.exists(Scanner::Trivy));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_downloaded_version_is_not_used() {
        let dir = temp_data_dir("sel-malformed");
        let volume = ScannerVolume::under(&dir);
        let scanner_dir = volume.scanner_dir(Scanner::Trivy);
        let folder = scanner_dir.join("9.9.9-rc1");
        if let Err(err) = std::fs::create_dir_all(&folder) {
            panic!("dir: {err}");
        }
        if let Err(err) = std::fs::write(folder.join("trivy"), "bin") {
            panic!("bin: {err}");
        }
        if let Err(err) = std::fs::write(scanner_dir.join("current"), "9.9.9-rc1\n") {
            panic!("pointer: {err}");
        }
        let (state, decision) = select(&volume, Scanner::Trivy, Some(v("0.76.2")));
        assert_eq!(state, ScannerState::BUNDLED);
        assert_eq!(decision, Decision::PurgedMalformed);
        assert!(!volume.exists(Scanner::Trivy));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_bundled_version_keeps_the_download_but_uses_the_bundled_one() {
        let (dir, volume) = setup("sel-unknown", "0.77.0");
        let (state, decision) = select(&volume, Scanner::Trivy, None);
        assert_eq!(state, ScannerState::BUNDLED);
        assert_eq!(decision, Decision::BundledUnknown);
        assert!(volume.has_binary(Scanner::Trivy, v("0.77.0")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_broken_or_missing_download_is_not_used_and_is_kept() {
        let (dir, volume) = setup("sel-broken", "0.77.0");
        volume
            .mark_broken(Scanner::Trivy, v("0.77.0"))
            .expect_test_ok();
        let (state, decision) = select(&volume, Scanner::Trivy, Some(v("0.76.2")));
        assert_eq!(state.selected, Selected::Bundled);
        assert_eq!(state.broken, Some(v("0.77.0")));
        assert_eq!(decision, Decision::Broken(v("0.77.0")));
        assert!(volume.exists(Scanner::Trivy));

        let _ = std::fs::remove_file(volume.binary_path(Scanner::Trivy, v("0.77.0")));
        let _ = std::fs::remove_file(
            volume
                .version_dir(Scanner::Trivy, v("0.77.0"))
                .join("broken"),
        );
        let (state, decision) = select(&volume, Scanner::Trivy, Some(v("0.76.2")));
        assert_eq!(state, ScannerState::BUNDLED);
        assert_eq!(decision, Decision::MissingBinary(v("0.77.0")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_launch_failure_marks_the_version_broken_and_falls_back_to_bundled() {
        let (dir, volume) = setup("sel-launch", "0.77.0");
        let programs = ScannerPrograms::bundled(&dir).select_at_startup([Some(v("0.76.2")); 2]);
        let (_, used) = programs.program(Scanner::Trivy);
        assert_eq!(used, Selected::Downloaded(v("0.77.0")));
        assert!(programs.launch_failed(Scanner::Trivy, used));
        assert_eq!(
            programs.state(Scanner::Trivy),
            ScannerState {
                selected: Selected::Bundled,
                broken: Some(v("0.77.0")),
            }
        );
        assert_eq!(
            programs.program(Scanner::Trivy).0,
            PathBuf::from("/usr/local/bin/trivy")
        );
        assert!(volume.is_broken(Scanner::Trivy, v("0.77.0")));
        // A restart does not pick the broken version again.
        let again = ScannerPrograms::bundled(&dir).select_at_startup([Some(v("0.76.2")); 2]);
        assert_eq!(again.state(Scanner::Trivy).selected, Selected::Bundled);
        assert_eq!(again.state(Scanner::Trivy).broken, Some(v("0.77.0")));
        // The bundled binary has nothing to fall back to.
        assert!(!programs.launch_failed(Scanner::Trivy, Selected::Bundled));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
