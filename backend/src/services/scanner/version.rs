//! Scanner release versions (#390): `MAJOR.MINOR.PATCH`, compared numerically per component, so
//! `0.76.10` is newer than `0.76.9`.
//!
//! Only three dotted components of 1 to 9 ASCII digits are accepted, with an optional leading
//! `v`, and no leading zero in a component of more than one digit. Anything else (a pre-release
//! suffix such as `-rc1`, a path separator, an empty part) is malformed: it is never newer, never
//! used, and never put into a path. The canonical text (`0.77.0`, no `v`) is the name of a
//! version folder on the data volume.

use std::fmt;

/// A parsed scanner version. Ordered numerically by major, minor, then patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

/// The most digits in one component.
const MAX_COMPONENT_DIGITS: usize = 9;

impl Version {
    /// Parses `0.77.0` or `v0.77.0`. `None` for anything else.
    pub fn parse(text: &str) -> Option<Self> {
        let bare = text.strip_prefix('v').unwrap_or(text);
        let mut parts = bare.split('.');
        let (Some(major), Some(minor), Some(patch), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        Some(Self {
            major: component(major)?,
            minor: component(minor)?,
            patch: component(patch)?,
        })
    }

    /// A version from its three components.
    #[cfg_attr(not(test), allow(dead_code))]
    pub const fn from_parts(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// The `vX.Y.Z` form used by the About route.
    pub fn tagged(&self) -> String {
        format!("v{self}")
    }
}

fn component(text: &str) -> Option<u64> {
    let valid = !text.is_empty()
        && text.len() <= MAX_COMPONENT_DIGITS
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && !(text.len() > 1 && text.starts_with('0'));
    if !valid {
        return None;
    }
    text.parse().ok()
}

impl fmt::Display for Version {
    /// The canonical text, `MAJOR.MINOR.PATCH`, with no `v`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        match Version::parse(text) {
            Some(version) => version,
            None => panic!("{text} should parse"),
        }
    }

    #[test]
    fn components_compare_numerically() {
        assert!(v("0.76.10") > v("0.76.9"));
        assert!(v("0.77.0") > v("0.76.99"));
        assert!(v("1.0.0") > v("0.121.3"));
        assert_eq!(v("v0.76.2"), v("0.76.2"));
    }

    #[test]
    fn the_canonical_text_has_no_v() {
        assert_eq!(v("v0.121.3").to_string(), "0.121.3");
        assert_eq!(v("0.121.3").tagged(), "v0.121.3");
    }

    #[test]
    fn malformed_versions_are_refused() {
        for text in [
            "",
            "v",
            "0.77",
            "0.77.0.1",
            "0.77.0-rc1",
            "0..1",
            "0.077.0",
            "../0.1",
            "0.1.x",
            "1234567890.0.0",
            "0.1.0/",
            " 0.1.0",
            "vv0.1.0",
        ] {
            assert_eq!(Version::parse(text), None, "{text:?} should be refused");
        }
    }
}
