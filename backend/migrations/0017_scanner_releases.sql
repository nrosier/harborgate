-- #390: the outcome of the daily upstream check, per scanner. Once a day Dockward asks the GitHub
-- latest-release API (no token) for aquasecurity/trivy and anchore/grype and stores the latest
-- stable release here, with whether it is newer than the bundled scanner. Pre-releases are never
-- stored. A failed check stores nothing, so the last good answer is kept. Public version numbers
-- only; nothing secret is held.
CREATE TABLE IF NOT EXISTS scanner_releases (
    scanner TEXT PRIMARY KEY CHECK (scanner IN ('trivy', 'grype')),
    latest_version TEXT NOT NULL,       -- canonical MAJOR.MINOR.PATCH, no leading v
    newer_than_bundled INTEGER NOT NULL CHECK (newer_than_bundled IN (0, 1)),
    checked_at INTEGER NOT NULL         -- Unix seconds
);
