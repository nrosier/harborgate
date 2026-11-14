# Changelog

All notable changes are recorded here. Versions follow semantic versioning.

## Unreleased

### Changed
- The CVE description in a new issue body is hard-wrapped at 80 characters inside its code fence, so it no longer scrolls sideways. Existing issues are not rewritten (#392).

### Fixed
- A tag that moves to a digest dockward has already scanned now queues a scan of that digest (trigger `tag_moved`), so the tag's CVE findings and the `Found by` line of its issues are rebuilt instead of staying stale. A repeated discovery queues no duplicate (#391).

### Added
- Scanner selection from the data volume, phase 1 (#390). The bundled Trivy and Grype stay the default. At startup a downloaded version under `<data dir>/scanners/<scanner>/<version>/` is used when it is newer than the bundled one (compared per component, so 0.76.10 > 0.76.9); an equal, older or malformed one is purged. One previous version is kept for rollback, which is a pointer change. A downloaded binary that does not start is marked broken and the bundled one takes over, so scans keep running. Once a day dockward asks the GitHub latest-release API (`api.github.com`, no token) for the latest stable Trivy and Grype release and stores it in the new `scanner_releases` table (migration 0017); a failed check is logged and records nothing. `GET /api/v1/about` adds a `scanners` object with the binary in use, a broken version and the last check. Nothing is downloaded yet (phase 2), and there is no screen yet.
- Open issues are refreshed on each scan: the description (wrapped as in a new issue) and the `Affected tags:` line follow the current scan, and a severity increase posts one comment naming the old and new severity. A decrease or no change posts none, and a closed issue is left alone (#393).
- The version in the header is a button that opens an About dialog with the dockward version, the bundled Trivy and Grype versions, and the full MIT and Apache-2.0 licence texts. The backend reads the scanner versions once at startup (`trivy --version`, `grype version`, 5 second timeout) and serves them from `GET /api/v1/about`; a failed read shows `unknown`. The image now carries the Trivy and Grype Apache-2.0 licence and notice texts and the dockward MIT licence under `/usr/share/licenses/` (#388).

## 0.8.0 - 2026-11-14

### Added
- False positive is a second verdict next to Accept risk on a CVE (`POST /api/v1/cves/:id/false-positive`, audited as `cve.false_positive`). It records the verdict with an optional note and expiry, comments on the open GitHub issue and never closes it, and blocks new issues like an acceptance. Un-accept clears either verdict, and the CVE detail shows which one is active (migration 0015).
- A GHSA or GO id that the scanner gives no CVE id for is looked up at OSV (`api.osv.dev`), then at GitHub advisories when OSV does not answer, and the record is stored under the CVE id the advisory names. The answer, including "no CVE id published", is cached for good in the new `advisory_lookups` table (migration 0016, #379). A failed lookup does not fail the scan, is not cached, and is retried on a later scan. Only the advisory id is sent.

### Changed
- Bundled scanners: Trivy v0.76.2, Grype v0.121.3 (unchanged from 0.7.0).

### Fixed
- An accepted CVE is flagged for re-review only when its severity or fix changes on the newest scanned digest of the source. A change on an older tag no longer sets the flag (#380).
- An open GitHub issue now follows a change of its CVE's severity: the old severity label is replaced with the new one (none for UNKNOWN), and the Severity row of the body is updated. Other labels and the rest of the body are kept, and nothing is commented, reopened or closed. A closed issue is left alone (#381).

### Upgrade notes
- Migration 0015 runs on first start. It adds `cve_acceptances.kind`; existing rows are `accepted`.
- Migration 0016 runs on first start. It adds the `advisory_lookups` table.
- Dockward now makes outbound HTTPS calls to `api.osv.dev` and `api.github.com` during a scan, for GHSA and GO ids only. Allow them if your network filters egress.

## 0.7.0 - 2026-11-13

### Changed
- Bundled scanners: Trivy v0.76.2, Grype v0.121.3 (unchanged from 0.6.0).
- Dockward no longer closes a GitHub issue when its CVE is fixed. It posts one note saying the CVE is no longer reported and the issue can be closed, and leaves the issue open for the user to close. The note is recorded in `github_issues.fixed_noted_at` (migration 0014) and is posted again only after the CVE has returned and been fixed again.

### Upgrade notes
- Migration 0014 runs on first start. It adds `github_issues.fixed_noted_at`.
- Issues of fixed CVEs are no longer closed automatically. Dockward posts one note and leaves the issue open.

## 0.6.0 - 2026-11-13

### Added
- Jobs carry a Subject and a real trigger, and each recent job shows what it did. Empty-output jobs can be hidden on the Jobs dashboard (migration 0010, #360).
- Each CVE records which scanners reported it, per tag (migration 0012, #366).
- A GHSA or GO vulnerability is linked to its CVE id, and the CVE detail shows the reason when no CVE id exists (migration 0013, #367).
- The bundled Trivy and Grype releases are recorded and checked on each release (#368).

### Changed
- Bundled scanners: Trivy v0.76.2, Grype v0.121.3 (pinned by digest in the Dockerfile, checked by `scripts/check-scanner-versions.sh`, #368).
- The CVE filter is kept when you open a CVE and go back, and a Clear filter button resets it (#363).
- When an accepted CVE returns, its issue is reopened. A changed acceptance is flagged for re-review, the flag can be cleared, and un-accepting a CVE reopens its issue (migration 0011, #196).
- Small items: catalog keys were tidied, and the stored empty flag on jobs is kept (#371, #360, #363, #368).

### Upgrade notes
- New migrations 0010 to 0013 run on first start. They add the job empty flag, the acceptance changed flag, the per-CVE scanner record, and the id reason field.

## 0.5.1 - 2026-11-13

### Added
- An admin who is not the owner of the source can un-accept a CVE (PR #356, #351).
- The CVE detail lists every image and tag where the CVE was found, with the status, last scan and fixed-in version. The list is capped at 100 tags, with a total shown beside it (PR #355, PR #357, #350).
- An accept note, which may be empty, is shown on the CVE detail with who accepted it and when (PR #353, #351).
- An admin can delete one CVE record for one source. The delete is refused while an acceptance is active. Shared image rows are kept (PR #352, #349).

### Changed
- Each scan-log line carries the scanner and the job kind. The db_update scanner shows in the Jobs UI, and each update step is logged on its own (PR #358, PR #354, #308).

### Fixed
- The log redaction masks a bare Basic credential, webhook URL path tokens and session cookie values (PR #354, #308).
- The CodeQL-flagged redaction test failure message no longer echoes a secret value (PR #354, #308).

### Upgrade notes
- There are no new migrations in this release.
- The admin delete of a CVE record and the accept note are optional features. Nothing needs migrating.

## 0.5.0 - 2026-11-12

### Added
- Optional TOTP two-factor sign-in for local accounts: enrol with a QR code (returned as SVG), enter a code at sign-in, use single-use recovery codes, and turn TOTP off with a code (migration 0009, PR #343, #344, #346, #341). OIDC sign-in is unchanged.
- Pull and Scan on each image in the source image table, acting on the image's first tag. A forced scan runs again even when that digest was already scanned (migration 0008 adds the manual trigger, PR #339, PR #347, #335).
- The CVE detail shows an alias line for a GHSA record that has a CVE id, and the CVE list shows the primary id (PR #345, #337).

### Changed
- CVE records are keyed by the CVE id when there is one, and GHSA ids are kept as aliases. Migration 0007 folds existing GHSA rows that carry a CVE alias into their CVE record. Acceptances and GitHub issues stay per source (PR #338, PR #340, PR #342, #337).
- The hourly pass checks each tag's digest and pulls only when it has changed. A repository whose latest discovery failed is queued again on the next pass (PR #336, #334).

### Upgrade notes
- The GHSA GitHub issues merged into a CVE stay open on GitHub. Close them by hand if you no longer want them.
- Migrations 0007 to 0009 add columns and tables and rewrite existing GHSA rows.
- An existing CVE gets its alias and image only after it is rescanned.
- The 0.4.0 and 0.4.1 notes still apply.

## 0.4.1 - 2026-11-12

### Changed
- Creating a source, or changing its repository, tag pattern or hub, queues discovery for it at once, instead of waiting for the next hourly pass. A rename on its own queues nothing, and a failed earlier discovery of the same repository no longer blocks a new source (PR #332, #331).

### Upgrade notes
- Sources already added keep showing "last discovery: not yet" until they are saved again or the hourly pass runs. Saving a source queues discovery only if its repository, tag pattern or hub changed.

## 0.4.0 - 2026-11-12

### Added
- A GHSA finding stores the first CVE id that the scanner names among its related vulnerabilities as its alias, and the CVE detail shows it beside the primary id (migration 0006, PR #329, #323).
- The CVE detail shows the image and the source's display name, and the header has a View issue action when an issue exists or a Create issue action for the source owner (PR #326, PR #327, PR #328, #323).
- Image sources have an optional display name, set in the source form. It is shown in place of the repository when set (migration 0005, PR #328, #323).
- Scan, publish and pull jobs store the image and the trigger, and the Jobs page shows them. Jobs queued before this release show a dash (PR #324).

### Changed
- An accepted CVE whose GitHub issue is closed stays closed when the CVE returns. No reopen call and no comment are made (PR #325, #196).
- The CVE list and the Jobs page take each row's repository from the source lookup. The Mapping filter sends the source id (PR #327, PR #328, PR #329, #323).

### Fixed
- The Jobs Mapping filter sends `source_id`, the key the jobs route reads, so the filter applies (PR #328, #323).
- The CVE detail loads its source instead of the removed mappings route, and the CVE list no longer calls the removed mappings routes (PR #326, PR #328, #323).

### Upgrade notes
- Migrations 0005 and 0006 only add nullable columns. No existing row is rewritten.
- An existing CVE gets its alias and image only after it is rescanned. The new scan fields apply to new scans, not to scans already stored (migration 0006 and the new scan fields).
- Jobs queued before this release keep their payloads and show a dash for image and trigger. There is no backfill.

## 0.3.1 - 2026-11-11

### Fixed
- The scanner's temp and home directories now live under the data volume, so a database download no longer fails with 'mkdir /.cache: read-only file system' or 'no space left on device' on a read-only root or a small /tmp (#321).

## 0.3.0 - 2026-11-11

### Changed
- GitHub identifiers are renamed to dockward. SARIF uploads use the tool and driver name `Dockward` and the category `dockward/<hub host>/<repository>/<tag>/`. New issues carry the label `dockward` and the marker `<!-- dockward:<CVE> -->`. The OCI branch label is `io.github.nrosier.dockward.branch`.
- One-time issue re-key: on the first publish to each GitHub repository, the `harborgate` label is renamed to `dockward` and the first line of each open old issue is rewritten to the new marker. Closed issues keep their old marker. Old issues stay adoptable under either the old label or the old marker (1-second pacing between writes).
- Old HarborGate Code Scanning analyses are retired automatically after a successful upload. Dismissals on clear rule groups are carried over to the new open alerts first, then the old analyses of the exact legacy category are deleted on every branch. Mixed groups are not carried over. Deletion cannot be undone, and alert history for those analyses is lost. A token needs the `repo` scope (classic) or "Code scanning alerts" write (fine-grained) for the delete.
- The CVE tag count is reworded, and the repository filter is named Namespace (#257, PR #315).
- db_update jobs show the scanner, jobs record real run timings, and the scan timeout is clamped (#308, PR #317).
- Failed and admin job times are shown in browser local time (#309).

### Added
- The branch label `io.github.nrosier.dockward.branch` is read and wins over the legacy `io.github.nrosier.harborgate.branch`, which is still read with a deprecation warning.
- Admins can open a job log in a wide dialog from the Jobs and admin Jobs pages, backed by per-step redacted scanner logs (#308, PR #318, PR #319).

### Upgrade notes
- A HarborGate database (`harborgate.db` or any database with the HarborGate `repo_mappings` table) is refused, not migrated. Dockward starts with a fresh `dockward.db`, and HarborGate data is not carried over.
- Stop any old HarborGate instance before you upgrade. If one is still running, it creates new `harborgate` issues after the re-key.
- Rename the OCI label `io.github.nrosier.harborgate.branch` to `io.github.nrosier.dockward.branch` in your image builds.
- Old categories of deleted sources are not removed automatically. Remove them by hand on the tool status page (docs/SETUP.md, section 10).

## 0.2.0 - 2026-11-11

This release is the first as dockward. HarborGate is renamed, the Harbor integration is removed, and images are scanned locally from any registry.

### Added
- Images come from any registry: ghcr.io and docker.io by default, with custom registries added by an admin (decisions 7, 11, 13, 44, 45).
- Images are pulled into local OCI layouts with no Docker daemon. Trivy and Grype run out of process from pinned binaries in the image (decisions 28, 29).
- Discovery runs hourly per repository; a new or moved tag queues one pull (decisions 16, 17).
- Each platform of a multi-arch image is scanned; attestation entries are skipped (decision 30).
- A daily database refresh rescans every stored image when a scanner database is newer (decision 4).
- Sources, hubs, credentials, tag preview, images and admin scan settings are served under /api/v1 (section 10).
- Sources and Images screens, a namespace filter on the CVE list, and "Scan now" on a source.

### Changed
- The product is named dockward. Environment variables are DOCKWARD_*; HARBORGATE_* still works as a logged fallback for this release (decision 57).
- The database is dockward.db. This is a fresh database: HarborGate data is not migrated, and an old HarborGate database is refused with an error. The stored-credential and HKDF labels are dockward/*, so stored credentials and sessions from HarborGate do not open; users create their credentials again and sign in again (decisions 54, 56).
- The session, CSRF and OIDC cookies are __Host-dockward_*. Existing sessions are rejected and users sign in again once.
- Sync jobs are jobs: the table, the /api/v1/jobs routes and the Jobs page (decision 58).
- The published image is ghcr.io/<owner>/dockward.

### Removed
- Harbor: the client, webhooks, polling, project scanners, scheduled Harbor scans and the robot permissions (decision 34).

### Fixed
- Sync and scan jobs show their real trigger instead of Webhook.
- The scanner environment always sets HOME inside the cache root, so Trivy no longer tries to write its cache to /.

## 0.16.0 - 2026-11-09

### Changed
- The runtime image is now `FROM scratch`: the static binary, the CA bundle, and `/data` and `/tmp` created in the image. It has no shell and no package manager. The healthcheck is `harborgate healthcheck`. The binary is built with `cargo auditable`, so image scans read the Rust dependencies (#269, PR #270, PR #271, PR #272).
- The image no longer contains apk, so the zlib upgrade in 0.15.1 is no longer needed.

### Fixed
- The backup directory is created at startup with mode 0700, so a fresh install can back up without a manual step (#273, PR #274, PR #275).

## 0.15.1 - 2026-11-09

### Fixed
- Rebuilt the image on Alpine 3.24 with zlib 1.4-r0, which fixes CVE-2026-4738 (Critical, zlib 1.3.2-r1 in the shipped image; Grype alert #73; issue #262).

## 0.15.0 - 2026-11-08

### Added
- CVE page control bar (#257, PR #258, PR #260): one search field; severity, status and GitHub-issue pills; one row of comboboxes with Mapping as the only scope control; the Tags n of m column; a confirmation before Create issue; URL state that keeps the old parameters working; and admins see every tenant's CVEs.

### Changed
- The status=open filter excludes accepted CVEs (#257, PR #260).
- The My Mappings / All Mappings toggle is removed; Mapping is the only scope control (#257, PR #260).
- A spec was added for the CVE page control bar (#257, PR #258).

## 0.14.0 - 2026-11-08

### Added
- Purge of failed sync jobs: a backend endpoint and a Purge failed jobs button on the Sync jobs page (#243, PR #245, PR #246).
- Dashboard card for accepted CVEs (#247, PR #253).
- Favicon from the HarborGate house mark (PR #248).
- Security scanning workflow with Syft, Grype and Trivy (#227, PR #252).

### Changed
- HarborGate removes the data of artifacts Harbor deleted. When Harbor no longer has the artifact for a tag (found on a poll or pull, or by a 404 in a sync or resolve job), the tag's findings, sync reports and sync jobs are deleted, and the scanner reports too when no other tag of the mapping holds the digest. GitHub issues and uploaded SARIF are kept. This supersedes the #197 rule: the done note "artifact no longer in Harbor" is no longer written for those artifacts, and existing rows keep it (#249, PR #254).
- No database migrations were added since 0.13.0; the latest remains 0010.
- Specs were added for purging failed jobs, the accepted-CVE card and the removal of deleted artifacts (#243, #247, #249, PRs #244, #250, #251).

## 0.13.0 - 2026-11-08

### Added
- Scanner reports: HarborGate stores one report per mapping, image digest and Harbor scanner, and merges them into one finding per CVE and package. SARIF results carry `harborgate/scannerCount` and `harborgate/scannerNames`, and issue bodies carry a "Found by N scanner(s)" line (#224, PR #235, PR #236, PR #237, PR #238).
- Scan launch with a chosen scanner: `GET /api/v1/mappings/:id/scanners` and `POST /api/v1/mappings/:id/tags/:tag/scan` run a scan with one Harbor scanner and restore the project's previous scanner afterwards (#224, PR #236, PR #237).
- `GET /api/v1/mappings/:id/tags/:tag/scans` returns the per-scanner scan state of a tag (#224, PR #238).
- `GET /api/v1/mappings/:id/tags` returns the tracked tags of a mapping with last scan time and open CVE count (#224, PR #240).
- Scans card on the mapping edit page: one row per tracked tag, the report state per scanner, and a Scan button with a scanner picker (#224, PR #239, PR #240).
- Scheduled scans run once per enabled scanner, and a webhook from another scanner fetches that scanner's report (#224, PR #238).
- Newest-digest CVE view: the CVE list and the dashboard count only the tags of each mapping's newest scanned digest. The CVE detail page lists older tags as "Older tag, not counted" (#196, PR #241).

### Changed
- Docker images are pushed to GHCR only on `v*` tags. A `v*` tag publishes `X.Y.Z`, `X.Y` and `latest`; `latest` moves to each release. Pushes to `main` push nothing, and the `sha-<7 hex>` tag is dropped (#227, PR #223).
- A CVE issue closes only when every enabled scanner has a report for the newest digest and none reports the CVE (#224, PR #237).
- The `Affected tags:` line of an issue lists every tracked tag that still reports the CVE (#196, PR #241).
- A scanner removed from Harbor has its reports deleted, and the findings, SARIF and issues follow (#224, PR #238).
- Migration 0009 adds `harbor_scanners` and `scanner_reports`; existing reports become the `unknown` scanner until the next normal sync (#224, PR #235).
- Migration 0010 adds the `newest_digest_tags` view (#196, PR #241).
- Specs for scanner reports, the newest-digest view, the security scanning workflow and the Grype reader were added or updated (#224, #196, #227, PRs #225 to #234).

## 0.12.5 - 2026-11-07

### Added
- Scheduled Harbor scan per mapping: off by default, daily or weekly at a UTC time. HarborGate asks Harbor to scan the newest tagged image and the Sync jobs page lists only the CVEs new for that image (#191, PR #221).
- Custom GitHub API and web base URL per instance, set by the admin in Settings > GitHub; the API base may carry a path such as `/api/v3`, and empty means github.com (#184, PR #206, PR #217).
- Mappings can be sorted by Harbor source, GitHub target, open issues and last sync, with sortable column headers (#190, PR #208, PR #209).
- After a mapping save, an inline banner proposes a project webhook when the Harbor project has none (#179, PR #219).
- HarborGate issues carry the `areai:security` label and a severity label (none for Unknown), and are titled "<CVE id> <package>"; adopted issues are renamed and get missing labels (#192, PR #214).

### Changed
- Several Harbor repositories may target one GitHub repository; issues are shared per GitHub repository and CVE. Migration 0007 drops the unique GitHub target rule (#185, PR #216).
- The picker greys out Harbor repositories that are already mapped, without naming the mapping or its owner (#189, PR #220).
- The Harbor robot needs Scan Create for scheduled scans; `docs/SETUP.md` lists it (#191, PR #221).
- Migration 0008 adds the scan schedule to `repo_mappings` and `cve_ids`, `new_cve_ids` to `sync_reports` (#191, PR #221).
- `docs/SETUP.md` documents the custom GitHub base URL setting (#184, PR #217).

### Fixed
- A sync or resolve job for an image deleted from Harbor is marked done with the note "artifact no longer in Harbor", not failed, with no retry or alert (#197, PR #203).
- Saving a duplicate Harbor repository shows one fixed message and no longer names the other mapping (#180, PR #218).

## 0.12.4

### Fixed
- CVE issues close when the newest scanned digest is clean, not when every tracked tag is clean (#196, PR #200).
- A manual close of a HarborGate issue on GitHub is honoured: HarborGate does not reopen it while the CVE stays, and posts no close comment on an issue already closed (#196, PR #200).

### Changed
- Migration 0006 adds `sync_reports.image_push_time` and `github_issues.closed_manually` (#196, PR #200).

## 0.12.3

### Fixed
- A child image of a tagged multi-arch index is marked done, covered by its parent index, instead of failing (#132, PR #194).

## 0.12.2

### Fixed
- Read OCI labels from Harbor's config and from index children, so multi-arch images sync (#132, PR #182).

## 0.12.1

### Changed
- The mapping screen is redesigned as side-by-side cards (#167).

### Fixed
- The mapping popup is no longer clipped, and the Harbor repository is disabled until a project is typed (#167).
- Every mapping save error shows fixed text (#167).

## 0.12.0

### Added
- Untagged scan events are resolved by the worker: an untagged `SCANNING_COMPLETED` vulnerability event with a valid digest stores one resolve job and returns 202, and the worker reads the digest's tags from Harbor (Artifact Read), keeps the newest 10 by push time, and queues one sync per tag (#132).
- A resolve rate limit (429) defers the job by `Retry-After`, or 5 minutes without it, capped at 1 hour, without using an attempt (#132).
- The job API reports each job's kind, `sync` or `resolve` (#132).
- Operators can verify the published image with cosign, documented in `docs/SETUP.md` (#171, #172).

### Changed
- The Harbor poller caps each digest to its newest 10 tags, the same cut as the resolve job (#132).
- A vulnerability event with a missing or invalid digest returns 400 (#132).
- Project webhook routing is scoped to the webhook's own Harbor project; events for other projects return 202 with nothing stored (#145).
- Unmatched repository names must pass Harbor's name rule and be at most 255 characters (#145).
- Project webhook create checks the secret before reading the body and the mapping budget (#145).
- `project_webhooks.rotated_at` no longer has an insert-time default (migration 0005) (#145).
- Every Docker build requires a `REVISION` build argument and sets the `org.opencontainers.image.revision` label, in both CI build steps (#169).
- `.hg-local` is git-ignored (#170).

### Fixed
- `docs/SETUP.md` no longer says untagged pushes are ignored (#132).
- Project webhook transfer, unmatched visibility and rotate-secret guards are covered by tests (#145).

### Security
- The publish job signs the image digest keyless with cosign and verifies the signature on the same digest, failing the job if verification fails (#171).
- `secret_hash` is redacted in the `ProjectWebhook` Debug output (#145).

## 0.11.0

### Added
- Mapping pickers: choose the Harbor project and repository and the GitHub repository from lists instead of typing them (#126).
- The mapping form suggests the GitHub source repository from the image's source label (#126).
- Per-instance hide and restore of picker items, with a Hidden tab to restore them (#126).
- Project webhook setup guide in `docs/SETUP.md` (#132).

### Changed
- The picker backend caps the upstream response body while reading it, and marks a Harbor list as truncated only when a further item exists (#126).
- A Harbor identity 5xx answers 502 instead of 422, and the picker 422 error carries a fixed detail code (#126).
- The setup guide documents the Repository List and Repository Read robot permissions (#126, #159).

### Fixed
- The suggested image tag is validated against the OCI tag grammar, and an artifact digest that is not `sha256:<64 hex>` is refused (#126).
- Picker cache ordering: cache slots are dropped and the generation bumped under one lock, a fill is not cached if its credential was updated meanwhile, and a deleted user's cache entries are dropped (#126).
- Hidden picker items are keyed by Harbor base URL (#126).

### Security
- The picker refuses an oversized upstream body before buffering it whole (#126).

## 0.10.1

### Fixed
- The app reports its real version. 0.10.0 shipped with the version still set to 0.9.1 in the code; this release sets it to 0.10.1 (the 0.10.0 image reports 0.9.1).

## 0.10.0

### Added
- Project webhook owner page and management API, with one Harbor webhook per project, rotation and unmatched repository counts (#132, #145).
- Manual scan pull for a mapping, a Pull scans button on the mapping page, and a 5-minute cooldown (#131).
- Admin application log page and an admin log level control that reverts after 30 minutes. Secrets are never logged (#136).
- All-severity CVE list with filters for severity, status, package, tag, project and repository, and manual GitHub issues for any severity, with a confirmation for LOW and UNKNOWN (#129).
- `PUT /api/v1/mappings/:id` for partial mapping edits (#130).
- Retry state and error shown for failing sync jobs (#135).
- A startup note that the image revision label is set explicitly (commit cd00199, no issue).

### Changed
- A missing image revision label is a permanent failure and is not retried (#141).
- The webhook auth value is shown as the full Authorization header, ready to paste into Harbor.
- The Account page is split into Profile, Appearance and Credentials tabs.
- The admin setup button explains why it is disabled when the passwords differ.

### Fixed
- A sync job no longer retries forever on a missing revision label (#141).
- A mapping update rebuilds from the locked row (#130).

## 0.9.1

### Fixed
- The container serves the web app. In 0.9.0 the release binary embedded no frontend files, so `/` returned a 404. The frontend is now embedded (#122).

### Added
- A startup log line with the version, bind address and non-secret settings. No key, token or secret is logged (#122).

## 0.9.0

First release candidate for HarborGate. Everything below is built on `main`; the live smoke test against real Harbor and GitHub (#43) is still open.

### Added
- Harbor webhook receiver and polling backup every 15 minutes, with digest dedupe (#28).
- Trivy-to-SARIF 2.1.0 converter, validated against the vendored schema (#26).
- GitHub code scanning SARIF upload and processing status (#27).
- Sync job handler that moves a Harbor report to SARIF upload (#53).
- GitHub issue lifecycle: create, adopt, close and reopen per CVE, and a manual issue route (#30, #54).
- Per-tag CVE findings with a 10-tag limit and fixed-detection (#29).
- CVE accept and un-accept with expiry (#31), and the CVE read APIs (#32).
- Jobs, admin jobs and dashboard read APIs (#55).
- Alert channels with encrypted config (#56), webhook and SMTP senders (#57), and alerts for failed syncs and new CRITICAL CVEs with 24 h dedupe (#33).
- Encrypted admin backup (HGBK1), offline restore and `harborgate rotate-key` (#40, #58, #41).
- Retention and cleanup worker with job_runs history (#34).
- Admin health route with per-target checks (#69).
- Frontend: shell, theme, string catalog, API client, login and setup pages, the Dashboard, Mappings, CVEs and Sync jobs pages, and the Account page with admin tabs (#36, #37, #38, #39).
- Docker image published by digest, scanned, then promoted with tags and signed (#3).

### Security
- Outbound HTTP through one checked client with an SSRF deny-list, no environment proxies, and resolved-address checks (#47, #57).
- Rate-limit and throttle state bounded (#46).
- Argon2 on the blocking pool with a concurrency cap (#45).
- OIDC sessions revoked on refused sign-in, with a race-safe first login (#49).
- Job worker supervised with panic isolation and a crash-loop limit (#48).
- Input origins, Harbor paths and names normalised, and API responses no-store (#50).
- Crypto dependencies upgraded (hmac, hkdf, sha2, aes-gcm, argon2, rand) with known-answer tests (#112, #113, #114).

### Fixed
- Shutdown drains within one 8 s budget, and manual sync retry is audited (#52).
- Harbor client probes the Issues permission on save (#21).
- Runtime image installs ca-certificates for outbound TLS (#90).
- Container uses Alpine 3.24 with a HEALTHCHECK (#2).

### Documentation
- Operator setup and restore docs aligned with the specs (#42), and the approved v1 screen designs recorded (#35).
