# Database

Purpose: schema reference for dockward 0.2.0's SQLite database, and the decisions behind each table.

## Source of truth

- `backend/migrations/0001_init.sql` is the schema. It is the only migration. The tables below describe it; if they disagree, the migration wins and this file is corrected.
- Migration `0008_manual_trigger.sql` (#335) adds `manual` to the `scan_runs.trigger` CHECK. SQLite cannot alter a CHECK, so it rebuilds `scan_runs` (copying every row with its `rowid`), then recreates `idx_scan_runs_current`, `newest_digest_tags` and `tag_scan_times` as in 0001. It starts with `-- no-transaction`: `PRAGMA foreign_keys` is a no-op inside a transaction, and foreign keys must be OFF while the old table is dropped, or the drop cascades into `scanner_findings`. The rebuild runs in its own `BEGIN`/`COMMIT` and ends with `PRAGMA foreign_key_check`.
- Fresh install only (decisions 21, 56). There is no import from a HarborGate database and no data migration. A database file that contains the `repo_mappings` table is refused at pool open with the fixed error `this database was created by HarborGate and cannot be used by this version` (`backend/src/db/mod.rs`). The database file is `<data dir>/dockward.db`.
- SQLx SQLite with WAL mode. Use `SqlitePool`. Every connection sets `PRAGMA foreign_keys = ON`.
- SQLite does not enforce foreign keys unless the pragma is on. NULL values are distinct for UNIQUE constraints.
- Timestamps are `INTEGER` UTC Unix seconds, with defaults from `unixepoch()` (Decided 2026-11-03). The API formats them as RFC 3339 ([api.md](api.md), Conventions).

## Tables

| Table | Purpose |
| --- | --- |
| `system_config` | Key-value settings: OIDC, GitHub URLs, scan settings, auth flags (see below). |
| `users` | Local and OIDC users. `token_version` is the session revocation counter. |
| `hubs` | Registries. `host` is the only identifier and the only name (decision 45). `kind` is `default` or `custom`. `pull_endpoint` is custom-only. The migration inserts `ghcr.io` and `docker.io` as default hubs. |
| `user_credentials` | GitHub credentials only, encrypted. |
| `image_sources` | A source: hub, repository (full path), tag value (exact or pattern), and its GitHub target. Owned by `user_id`. |
| `source_credentials` | At most one registry credential per source, encrypted. |
| `images` | One row per (hub, repository, top-level digest). `is_index` says whether it is an index. |
| `tag_observations` | Which digest a source's tag pointed to, and when discovery first saw it. |
| `image_platforms` | One row per platform manifest. Each `stored` row is one OCI layout on disk. `state` is `queued`, `pulling`, `stored`, `evicting`, `evicted`, or `failed`. |
| `scanner_databases` | Per scanner (`grype`, `trivy`): the database version in use and when it was built. |
| `jobs` | The durable job queue (see [backend.md](backend.md)). |
| `scan_runs` | One scan of one platform image by one scanner. Append-only history. |
| `scanner_findings` | Findings of one scan run, one row per (run, CVE, package). |
| `publish_reports` | The SARIF upload record for each publish. |
| `github_issues` | Tracked GitHub issues, one per (owner, repo, CVE). Shared by every source that targets that GitHub repository. |
| `cve_findings` | One row per (source, tag, CVE): the merged view of the tag's current image. |
| `vulnerability_aliases` | Global, public ids only: one row per GHSA or GO id, pointing at its CVE id (migration 0007, #337). Written from scanner reports and from advisory lookups. |
| `advisory_lookups` | Global, public ids only: the cached answer of an advisory lookup, one row per GHSA or GO id (`advisory_id`): `cve_id` (NULL when none is published), `looked_up_at`, `source` (`osv` or `github`). Kept forever. Failed lookups are not stored. Migration 0016 (#379). |
| `scanner_releases` | Global, public version numbers only: the last successful daily upstream check per scanner (`scanner` is `trivy` or `grype`, the key): `latest_version` (canonical `MAJOR.MINOR.PATCH`, the latest stable GitHub release), `newer_than_bundled` (0 or 1), `checked_at`. A failed check writes nothing, so the last good answer stays. Migration 0017 (#390). |
| `cve_acceptances` | Accepted risk or a false-positive verdict, per source and CVE. |
| `totp_secrets` | One row per local user who started TOTP enrolment: the sealed secret, `enabled`, `totp_last_step` (replay guard), timestamps. Migration 0009 (#341). |
| `totp_recovery_codes` | Argon2id hashes of a user's recovery codes and `used_at`. Migration 0009 (#341). |
| `audit_log` | Admin and security-relevant actions. |
| `alert_channels` | SMTP and webhook destinations, encrypted. |
| `alert_deliveries` | The 24-hour alert dedupe log. |
| `job_runs` | Housekeeping run history (`cleanup`, `retention`, `discover`, `db_update`). Counts and error text only. |

Views: `newest_digest_tags` (the tags of a source's newest image, decision 49) and `tag_scan_times` (when each tag was last scanned). Both are read by the CVE list and the dashboard.

Removed from HarborGate: `repo_mappings`, `sync_jobs`, `sync_reports`, `project_webhooks`, `project_webhook_unmatched`, `picker_hidden_items`, `harbor_scanners`, `scanner_reports`, `project_scanner_locks`. The scanner-lock table and its rules are gone with Harbor.

Column names that changed from HarborGate: `sync_job_id` is `job_id` where it names a row of `jobs`. `sync_report_id` is `publish_report_id`. `mapping_id` is `source_id`. `harbor_repository` is `repository`. `harbor_project` is dropped.

## Key columns

- `hubs`: `host` UNIQUE. `pull_endpoint` is NULL for default hubs. `CHECK (pull_endpoint IS NULL OR kind = 'custom')`.
- `image_sources`: `UNIQUE (hub_id, repository, tag_value)`. This is the source identity (decisions 33, 37). The same repository on two hubs is two sources. No user is part of the key. `github_cred_id` is `NOT NULL` with `ON DELETE RESTRICT`. `min_issue_severity` is `CRITICAL` or `HIGH`.
- `source_credentials`: `source_id` UNIQUE. Ciphertext AAD `source_credentials:encrypted_token:<id>` (decision 35).
- `image_platforms`: `UNIQUE (image_id, platform_digest)`. `pulled_at` is the eviction clock. Index `idx_image_platforms_evict` on `(state, pulled_at, id)`.
- `scan_runs`: `trigger` is `first_pull`, `tag_moved`, `db_update`, or `manual` (a forced scan from the source page, #335; migration `0008_manual_trigger.sql`). `job_id` is `ON DELETE SET NULL`.
- `scanner_findings`: `package` is `''` when the scanner gives none. `severity` is one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`. `description` is at most 4,000 characters.
- `publish_reports`: `source_id` cascades. `image_id` and `job_id` are `ON DELETE SET NULL`.
- `github_issues`: `UNIQUE (github_owner, github_repo, cve_id)`. `closed_manually` is `0` or `1`. `fixed_noted_at` is a nullable Unix-seconds timestamp: set when Dockward posted the "fixed, can be closed" note for the CVE, cleared when the CVE is reported again or the row status is set (migration `0014_fixed_note.sql`, "note only" decision of 2026-11-13, see [cve-lifecycle.md](cve-lifecycle.md)). Rows are never deleted by retention or by a source delete.
- `cve_findings`: `UNIQUE (source_id, image_tag, cve_id)`. `status` stores only `open` or `fixed`. `github_issue_id` is `ON DELETE SET NULL`.
- `cve_acceptances`: at most one active acceptance per source and CVE, of either kind (partial unique index `idx_cve_acceptances_active` on `(source_id, cve_id) WHERE revoked_at IS NULL`). `CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))`. `kind` is `accepted` or `false_positive`, `NOT NULL DEFAULT 'accepted'` (migration `0015_acceptance_kind.sql`, 2026-11-13; rows written before it are `accepted`). See [cve-lifecycle.md](cve-lifecycle.md), "False positive".
- `job_runs`: `job_kind` is one of `cleanup`, `retention`, `discover`, `db_update`.

The #311 re-key bookkeeping tables (migration `0002_github_rekey.sql`):

```sql
-- GitHub re-key bookkeeping (#311, migration 0002_github_rekey.sql). Names and owners are case-insensitive (NOCASE).
-- One row per repository once its issues have been re-keyed (label renamed, old issues adopted).
CREATE TABLE IF NOT EXISTS issue_rekeys (
    github_owner TEXT NOT NULL COLLATE NOCASE,
    github_repo TEXT NOT NULL COLLATE NOCASE,
    label_result TEXT NOT NULL CHECK (label_result IN ('renamed', 'absent', 'kept')),
    issues_rekeyed INTEGER NOT NULL CHECK (issues_rekeyed >= 0),
    completed_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (github_owner, github_repo)
);
-- One row per repository and legacy SARIF category once its old HarborGate analyses have been retired (dismissals carried over, old analyses deleted).
CREATE TABLE IF NOT EXISTS analysis_retirements (
    github_owner TEXT NOT NULL COLLATE NOCASE,
    github_repo TEXT NOT NULL COLLATE NOCASE,
    legacy_category TEXT NOT NULL,
    analyses_deleted INTEGER NOT NULL CHECK (analyses_deleted >= 0),
    dismissals_carried INTEGER NOT NULL CHECK (dismissals_carried >= 0),
    completed_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (github_owner, github_repo, legacy_category)
);
-- The carry-over plan of one repository and legacy category, written before the first delete (#311 slice 6b). One row per rule that is carried; `applied` is set once that dismissal has been written.
CREATE TABLE IF NOT EXISTS alert_carryovers (
    github_owner TEXT NOT NULL COLLATE NOCASE,
    github_repo TEXT NOT NULL COLLATE NOCASE,
    legacy_category TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    comment TEXT,
    planned_at INTEGER NOT NULL,
    applied INTEGER NOT NULL DEFAULT 0 CHECK (applied IN (0, 1)),
    PRIMARY KEY (github_owner, github_repo, legacy_category, rule_id)
);
-- The refs the legacy analyses ran on, recorded with the plan so a retry uses the same set even after the analyses are deleted (#311 slice 6b).
CREATE TABLE IF NOT EXISTS carryover_refs (
    github_owner TEXT NOT NULL COLLATE NOCASE,
    github_repo TEXT NOT NULL COLLATE NOCASE,
    legacy_category TEXT NOT NULL,
    git_ref TEXT NOT NULL,
    PRIMARY KEY (github_owner, github_repo, legacy_category, git_ref)
);
```

## system_config keys

Each key is a row. Values are TEXT. Decided (2026-11-03, delegated) unless noted.

- `oidc.issuer_url`, `oidc.client_id`, `oidc.role_claim`, `oidc.admin_group`, `oidc.user_group`: `is_encrypted = 0`.
- `oidc.client_secret_encrypted`: `is_encrypted = 1`, a `v1:` ciphertext.
- `github.api_base_url`, `github.web_url`: custom GitHub URLs. Empty or missing means the defaults (Decided 2026-11-06, #184).
- `auth.oidc_only_users`: `true` or `false`. A missing row means `false`.
- `images.max_stored`: the count-based retention limit, default 20 (decision 18).
- `scanners.enabled`: which scanners run.
- `scanner.timeout_s` (600), `scanner.output_max_bytes` (64 MB), `pull.max_bytes_per_image` (10 GB), `disk.min_free_bytes_before_pull` (10 GB) (decision 19). Stored in bytes.

Source for the OIDC claim model: OpenID Connect Core 1.0.

## Audit action vocabulary

`audit_log.action` must be one of these values. Add a value here before writing it. Decided (2026-11-03, delegated), with the spinoff changes of spinoff-local-scan section 9.

- Kept: `user.create`, `user.delete`, `user.role_change`, `oidc.config_change`, `credential.create`, `credential.rotate`, `credential.delete`, `cve.accept`, `cve.unaccept`, `cve.review`, `alert.config_change`, `backup.run`, `restore.run`, `key.rotate`, `retention.run`, `log.level_change`, `sync_job.retry`, `sync_job.purge`.
- Added (#341, TOTP): `user.totp_enable`, `user.totp_disable`, `user.totp_reset` (admin action; target `user:<id>`; no details), `user.totp_lockout` (actor is the locked user; `details` is `{"failures": n}`). None carries a code, a secret or a hash.
- Added (spinoff): `hub.create`, `hub.delete`, `source.create`, `source.update`, `source.delete`, `source.scan`, `source.tag_pull`, `source.tag_scan` (#335; details hold the source id, the tag and the queued count), `image.evict` (actor `system`; details name the hub, repository, and platform digest, never a path with a secret), `settings.change` (scan limits and retention; details hold the old and new values).
- Added (2026-11-13, False positive): `cve.false_positive` (target `cve:<source_id>:<cve_id>`; `details` is `{"cve_id", "source_id", "expires_at"}` like `cve.accept`; the note is never in it).
- Removed (spinoff): `mapping.*`, `project_webhook.*`, `artifact.remove`, `key.migrate_labels`. The `key.migrate_labels` action belonged to the label migration that decision 56 removed.

- `github.rekey_issues` (the one-time re-key of a repository's GitHub issues, decision 60, issue #311; actor `system`; target `<owner>/<repo>`; `details` is `{"issues", "label"}`: `issues` is the count of old issues re-keyed and `label` is `renamed`, `absent`, or `kept`, the same text stored in `issue_rekeys.label_result`. It carries a count and a fixed word, never a token or a name; written once when the re-key completes). Source: `backend/src/services/issue_rekey.rs` (`AUDIT_ACTION`, `json!`). Verified (2026-11-11) by grep of `backend/src/services/audit.rs` ACTIONS.
- `github.retire_analyses` (the one-time retirement of a legacy `harborgate` SARIF category's analyses, decision 60, issue #311; actor `system`; target `<owner>/<repo>`; `details` is `{"analyses", "dismissals"}`: the counts of analyses deleted and dismissals carried to the new alerts. Count only; written once when the retirement completes). Source: `backend/src/services/legacy_analyses.rs` (`AUDIT_ACTION`, `json!`). Verified (2026-11-11) by grep of `backend/src/services/audit.rs` ACTIONS.

- `cve.delete` (#349; admin deletes one CVE record of one source; target `source:<id>`; `details` is `{"source_id", "cve_id"}`, ids only). Source: `backend/src/services/cves.rs` (`delete_record`).

`sync_job.retry` and `sync_job.purge` keep their names (decision 58). Their `target` is the fixed text `sync_jobs`, as written by `backend/src/services/jobs.rs`.

CONFLICT: the code at `origin/main` (`backend/src/services/audit.rs`, `ACTIONS`) still lists the removed actions `mapping.create`, `mapping.update`, `mapping.delete`, `mapping.pull`, `mapping.scan`, `mapping.webhook_token_rotate`, `mapping.auth_secret_rotate`, `project_webhook.*`, `artifact.remove`, and `key.migrate_labels`. It already lists the added `source.*`, `hub.*`, `image.evict`, and `settings.change`. Unresolved until the code is reconciled with the vocabulary above.

## Table decisions

- **Source identity** (decisions 33, 37): a source is hub, repository, and tag value. The namespace is the first segment of `repository` and is not stored. No project table or project column exists.
- **Credentials** (decisions 35, 39 to 43): credentials are per source, never per namespace or hub. Docker Hub is optional. A `ghcr.io` credential is a classic personal access token with `read:packages`.
- **Newest image** (decision 49): the newest image of a source is the tag observation with the latest `first_seen_at` for that tag. A tag that moves to a new digest becomes newest on the next discovery.
- **Shared issues** (decision 47): one `github_issues` row per (GitHub repository, CVE). Sources that target the same GitHub repository share it. The fixed note is posted only when no source for that repository reports the CVE; Dockward never closes an issue. Deleting a source never closes or changes an issue on GitHub.
- **Retention** (spinoff section 9): `publish_reports` and `scan_runs` are kept 90 days, except that the latest `done` run per (platform image, scanner) is never deleted. `jobs` and `job_runs` are kept 90 days. `alert_deliveries` are kept 30 days. `audit_log` is kept 365 days. `images`, `tag_observations`, and `image_platforms` are not under age retention.
- **Failed-job purge** (decisions 1 to 4 of #243): deletes `jobs` rows with `status = 'failed'` in scope and nothing else. `publish_reports.job_id` becomes NULL when its job is deleted, and the report stays.
- **Alert dedupe** (Decided 2026-11-03, delegated): the 24-hour window is enforced by the upsert `INSERT ... ON CONFLICT (channel_id, dedupe_key) DO UPDATE SET sent_at = excluded.sent_at WHERE alert_deliveries.sent_at < unixepoch() - 86400`. Send only when one row changed. Job failure keys are `job_failed:<job id>`.
- **Retention clock** (decision 18): eviction deletes the OCI layout only. The `image_platforms` row stays with state `evicted`, and findings and scan history stay.
- **Foreign keys on user deletion** (Decided 2026-11-03, delegated): the user deletion order is `image_sources`, then `user_credentials`, then `users`. `created_by`, `revoked_by`, and `actor_user_id` are `ON DELETE SET NULL`, with `*_username` snapshots kept for attribution.

## Decisions log

- Decided (2026-11-03): one job table for every unit of work, and no sync jobs (decision 58).
- Decided (2026-11-03, delegated): the derived-key labels are `dockward/credentials-v1`, `dockward/session-v1`, `dockward/backup-v1`, and `dockward/csrf-v1` (decision 54). The label names are in `backend/src/auth/crypto.rs`.
- Decided (2026-11-11): a fresh database only. The label migration (decision 56) and its tests were removed (PR #307).
