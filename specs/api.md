# API

Purpose: the HTTP route contract between the frontend and the backend. One place for every route, its auth level, and its status codes.

Decided (2026-11-03, delegated) the conventions below. The route list is taken from `backend/src/main.rs`, which is the source of truth. Routes not in `main.rs` are marked "not built". Field-level request and response shapes are the spinoff targets (spinoff-local-scan section 10). They are not re-verified against the handlers in this pass (UNVERIFIED).

## Conventions

- Base path `/api/v1`. Exceptions: `GET /healthz` and the static asset routes.
- Caching: every response under `/api/` carries `Cache-Control: no-store` (Decided 2026-11-04, #50).
- Format: JSON request and response bodies. Casing is snake_case. Timestamps are RFC 3339 UTC strings.
- IDs are opaque strings (the `TEXT` primary keys in [database.md](database.md)).
- Secrets are never returned. Registry tokens, GitHub tokens, the OIDC client secret, and alert channel secrets are write-only.
- Auth levels:
  - `public`: no session.
  - `session`: a valid session cookie. A `user` sees and changes only their own objects. A request for another tenant's object returns `404`, not `403`.
  - `admin`: a valid session whose role, looked up from `users.role` on this request, is `admin`. Admins read all tenants and may change only the operational routes listed in [security.md](security.md), Tenancy.
- CSRF: the signed double-submit cookie `__Host-dockward_csrf` (HMAC key from the HKDF label `dockward/csrf-v1`). Every `POST`, `PUT`, `PATCH`, and `DELETE` under `/api` requires the `X-CSRF-Token` header, except login and setup, which use the same-origin check in [security.md](security.md). A missing or wrong token returns `403` with code `csrf_invalid`.

### Error envelope

Every non-2xx response has this body, with a snake_case `code` and a safe `message`:

```json
{"error": {"code": "<snake_case>", "message": "<safe text>"}}
```

The envelope may carry an optional fixed `detail` code. `message` never contains a secret, a token, a stack trace, or SQL.

Codes: `invalid_request` (400), `password_too_short` (400), `unauthenticated` (401), `invalid_credentials` (401), `forbidden` (403), `csrf_invalid` (403), `not_found` (404), `conflict` (409), `validation_failed` (422), `payload_too_large` (413), `rate_limited` (429), `internal_error` (500), `upstream_unreachable` (502), `code_scanning_unavailable` (422).

### Lists

- List routes take `page` (1-based), `page_size`, `sort`, and `order` (`asc` or `desc`). Pagination is page-based.
- `page_size` defaults to 50 and has a maximum of 200. A larger value returns `400 invalid_request`. A `sort` value not in the route's allowed list returns `400 invalid_request`.
- Response shape: `{"items": [...], "page": 1, "page_size": 50, "total": 0}`.

### Rate limits

Every route that calls an outbound service or starts work declares its limit. Over the limit the response is `429` with `Retry-After` (RFC 6585, RFC 9110). Limits are held in memory and cleared by a restart. The values are the spinoff values (spinoff section 10):

- TOTP codes: 5 wrong codes per account per 15 minutes (`api/totp.rs`, `AppState::totp_limiter`). The fifth locks the account's code step until the window ends and writes `user.totp_lockout` once (#341).
- Login: 10 per minute per client IP (Decided 2026-11-03, delegated, [security.md](security.md)).
- Routes that call a registry or GitHub for a list or a test: 60 per minute per user.
- Manual scan of one source: 1 per source per 5 minutes (`POST /api/v1/image-sources/:id/scan`).
- Manual pull or forced scan of one tag: 1 per action, source and tag per 5 minutes (`POST /api/v1/image-sources/:id/tags/:tag/pull` and `.../scan`). It shares the in-memory limiter of "Scan now" under the key `tag:{action}:{source}:{tag}`, so it never uses the source's "Scan now" slot. A request refused with `404` or `409` uses no slot.
- Job purge: none, on purpose (Decided 2026-11-08, #243). It needs a session and a CSRF token, and deletes only rows the caller may retry.
- Health (`/healthz`): excluded.

UNVERIFIED in this pass: which of these limiters is implemented on which route. The limiter types are in `api/credentials.rs`, `api/admin.rs`, `api/sources.rs`, `api/hubs.rs`, `api/scan.rs`, `api/auth.rs`, and `api/hardening.rs`.

## Auth

| Method | Path | Auth | Built | Notes |
| --- | --- | --- | --- | --- |
| GET | `/api/v1/auth/setup-status` | public | yes | `{"setup_required", "oidc_enabled"}`. |
| POST | `/api/v1/auth/setup` | public | yes | Allowed only while `users` is empty. Sets session and CSRF cookies. Closes permanently after the first account. |
| POST | `/api/v1/auth/login` | public (same-origin check) | yes | `401 invalid_credentials` for every login failure. For a user with TOTP on, a correct password returns `200 {"totp_required": true}` and the `__Host-dockward_totp` challenge cookie (5 minutes), and no session (#341). |
| POST | `/api/v1/auth/logout` | session | yes | Clears the cookie. |
| POST | `/api/v1/auth/logout-all` | session | yes | Increments `users.token_version`. |
| GET | `/api/v1/auth/oidc/start` | public | yes | `404` while OIDC is not configured. |
| GET | `/api/v1/auth/oidc/callback` | public | yes | Every outcome is `302` once OIDC is configured (Decided 2026-11-03, delegated, #49). |
| GET | `/api/v1/account/me` | session | yes | `{"user"}`. |
| POST | `/api/v1/account/password` | session | yes | Minimum 15 characters, maximum 64 (Decided 2026-11-03). Increments `token_version`. |
| POST | `/api/v1/auth/totp/verify` | public (same-origin check, challenge cookie) | yes | Body `{"code"}`: a 6-digit TOTP code or a recovery code. Success sets the session and CSRF cookies. Every failure is the `401 invalid_credentials` of a wrong password. `429` with `Retry-After` while the account is locked (#341). |
| GET | `/api/v1/account/totp` | session | yes | `{"enabled"}` and nothing else (#341). |
| POST | `/api/v1/account/totp/enrol` | session | yes | `{"secret","otpauth_uri","qr_svg"}`, shown once; `qr_svg` is an SVG document of the URI. Stored sealed and disabled. `403` for an OIDC account, `409` when TOTP is on (#341). |
| POST | `/api/v1/account/totp/confirm` | session | yes | Body `{"code"}`. A valid code turns TOTP on and returns `{"recovery_codes"}` (10), once. `422 validation_failed` for a wrong code (#341). |
| POST | `/api/v1/account/totp/disable` | session | yes | Body `{"code"}`: a valid current TOTP code. `204`. `422` for a wrong code (#341). |

## Credentials (GitHub only)

A credential is `{"id","label","expires_at","created_at"}` and never contains the token. Registry credentials are not here; they belong to a source (below).

| Method | Path | Auth | Built | Notes |
| --- | --- | --- | --- | --- |
| GET | `/api/v1/credentials` | session | yes | List. |
| POST | `/api/v1/credentials` | session | yes | Create. |
| PUT | `/api/v1/credentials/:id` | session (owner) | yes | Update. |
| DELETE | `/api/v1/credentials/:id` | session (owner) | yes | `409` while a source uses it. |
| POST | `/api/v1/credentials/:id/test` | session (owner) | yes | GitHub test. Picks the first repository the token sees and runs the three probes on it. Decided (2026-11-06, #178). |
| GET | `/api/v1/credentials/:id/github-repositories` | session (owner) | not built | Spinoff section 10 keeps it. Absent from `main.rs`. |

## Hubs

A hub is `{"id","host","pull_endpoint","kind"}`. It has no display name and no label (decision 45).

| Method | Path | Auth | Built | Notes |
| --- | --- | --- | --- | --- |
| GET | `/api/v1/hubs` | session | yes | List. |
| POST | `/api/v1/hubs` | admin, limited | yes | `{"host","pull_endpoint"?}`. Validates the host grammar, the endpoint grammar, and the address rules ([security.md](security.md), Outbound HTTP). `kind` is `custom`. |
| DELETE | `/api/v1/hubs/:id` | admin | yes | `409` if a source uses the hub, or for a default hub (decision 13). |

## Image sources

A source is `{"id","hub_id","repository","tag_value","github_owner","github_repo","default_branch","auto_create_issues","min_issue_severity","has_credential","last_discovery_at"}`. It never contains the token. Registry credentials are attached to a source, one per source (decision 35).

| Method | Path | Auth | Built | Notes |
| --- | --- | --- | --- | --- |
| GET | `/api/v1/image-sources` | session | yes | List. Admin may add `scope=all`. |
| POST | `/api/v1/image-sources` | session | yes | Create. `409` on a duplicate (hub, repository, tag value). |
| GET | `/api/v1/image-sources/:id` | session (owner; admin read) | yes | |
| PUT | `/api/v1/image-sources/:id` | session (owner) | yes | |
| DELETE | `/api/v1/image-sources/:id` | session (owner) | yes | Removes the source's rows. GitHub issues stay open. |
| PUT | `/api/v1/image-sources/:id/credential` | session (owner) | yes | `{"username","token","expires_at"?}`. The token is write-only. On `ghcr.io`, a token starting `github_pat_` is `422`. |
| DELETE | `/api/v1/image-sources/:id/credential` | session (owner) | yes | On `docker.io` the source falls back to anonymous pulls (decision 42). |
| POST | `/api/v1/image-sources/:id/credential/test` | session (owner), limited | yes | `{"repository"}`. Returns `ok` or the failure, never the token. Works anonymously when no credential is set (decision 41). |
| GET | `/api/v1/image-sources/:id/tag-preview` | session (owner), limited | yes | `{"matches","truncated"}`. Names only; records nothing. |
| POST | `/api/v1/image-sources/:id/scan` | owner or any admin, limited | yes | Runs discovery for this source now. `{"queued": n}`. |
| POST | `/api/v1/image-sources/:id/tags/:tag/pull` | owner or any admin, limited | yes | Manual pull (#335) of the image the tag points at now. One `pull` job with trigger `manual` per platform; an `evicted` platform goes back to `queued` first; a platform whose pull job is queued or running is skipped. A stored platform is downloaded again into a temporary folder, every digest is verified, the copy is discarded and `pulled_at` is updated; stored files are not replaced. It forces no scan. `{"queued": n}`. `404` for a missing or foreign source, an invalid tag, or a tag the source has not observed. `409` while a platform is `pulling` or `evicting`. `429` with `Retry-After` for the same tag within 5 minutes. Audit `source.tag_pull`. |
| POST | `/api/v1/image-sources/:id/tags/:tag/scan` | owner or any admin, limited | yes | Forced scan (#335) of the image the tag points at now. One run with trigger `manual` per `stored` platform and enabled scanner, also for a digest already scanned; nothing is queued for a scanner whose run is queued or running. `{"queued": n}`. Same `404` and `429` rules as the pull route. Audit `source.tag_scan`. |
| GET | `/api/v1/image-sources/:id/images` | session (owner; admin read) | yes | Images of the source with per-platform state. |
| GET | `/api/v1/image-sources/:id/tags` | session (owner; admin read) | yes | Tracked tags. |
| GET | `/api/v1/image-sources/:id/cves` | session (owner; admin read) | yes | CVE list of the source. |
| GET | `/api/v1/images` | session | yes | Stored images across sources. Admin may add `scope=all`. |

## Scan settings (admin)

| Method | Path | Auth | Built | Notes |
| --- | --- | --- | --- | --- |
| GET | `/api/v1/admin/scan-settings` | admin | yes | `{"max_stored","scanners_enabled","scanner_timeout_s","scanner_output_max_bytes","pull_cap_bytes","min_free_disk_bytes"}`. |
| PUT | `/api/v1/admin/scan-settings` | admin | yes | Same shape. `422` for an out-of-range value. |

## Jobs

A job is `{"id","source_id","kind","status","attempts","next_attempt_at","last_error","created_at","updated_at","image"}`. `kind` is `discover`, `pull`, `scan`, `publish`, or `db_update` (decision 58). `status` is `queued`, `running`, `done`, or `failed`.

| Method | Path | Auth | Built | Notes |
| --- | --- | --- | --- | --- |
| GET | `/api/v1/jobs` | session | yes | List. Filters `status`, `source_id`, `hide_empty` (default off; leaves out jobs that produced nothing new, #360). Admin may add `scope=all`. Every job has a `trigger`; one with none in its payload is `scheduled`. |
| GET | `/api/v1/jobs/failed-count` | session | yes | `{"count"}` for the purge confirmation. `scope=all` for admins only. |
| POST | `/api/v1/jobs/purge-failed` | session (owner) or admin | yes | Deletes `failed` rows in scope. `{"deleted"}`. `scope=all` for admins only; a regular user who sends it gets `403`. One `sync_job.purge` audit row when at least one row is deleted. |
| GET | `/api/v1/jobs/:id` | session | yes | |
| POST | `/api/v1/jobs/:id/retry` | session (owner) or admin | yes | Re-queues a `failed` job. `409` for any other status. |

Decided (2026-11-08, #243): the purge ignores the page's `status` and `source_id` filters. It always covers every failed job in the scope.

## Dashboard

| Method | Path | Auth | Built | Notes |
| --- | --- | --- | --- | --- |
| GET | `/api/v1/dashboard/summary` | session | yes | `{"open_cves","fixed_cves","accepted_cves","open_issues","failed_syncs","recent_syncs"}` (`services/dashboard.rs`). Admin may add `scope=all`. Counts follow the newest scanned digest of each source ([cve-lifecycle.md](cve-lifecycle.md)). |

## About

| Method | Path | Auth | Built | Notes |
| --- | --- | --- | --- | --- |
| GET | `/api/v1/about` | session | yes | `{"dockward","trivy","grype","scanners"}` (`api/about.rs`, `services/about.rs`). `dockward` is the backend's `CARGO_PKG_VERSION`. `trivy` and `grype` are `vX.Y.Z` strings read once at startup by running `/usr/local/bin/trivy --version` and `/usr/local/bin/grype version`, or `null` when a read failed. Each read has a 5 second timeout, an empty environment but the scanner allow-list, and no stdin. Only the binary name and the outcome are logged, never the output. A failed read never stops startup (#388). `scanners` (#390) holds `trivy` and `grype`, each `{"in_use","downloaded_version","broken_version","latest_version","update_available","checked_at"}`: `in_use` is `bundled` or `downloaded`; `downloaded_version` is the downloaded version in use or `null`; `broken_version` is a downloaded version that failed to launch or `null`; `latest_version` and `checked_at` (RFC 3339) come from the last successful daily check or are `null`; `update_available` is true when that release is newer than the bundled scanner and than a downloaded version in use. Versions are `vX.Y.Z`. No path is returned. |

## CVEs

`{id}` is `<source_id>:<cve_id>`, URL-encoded. A CVE is listed for its source's newest image only. A CVE open only on an older tag is not in the list.

| Method | Path | Auth | Built | Notes |
| --- | --- | --- | --- | --- |
| GET | `/api/v1/cves` | session | yes | List. Filters below. Admin may add `scope=all`. |
| GET | `/api/v1/cves/:id` | session | yes | `CveDetail`. `200` for any CVE with a row on a tracked tag, including older tags (`older_tags_only`, `newest_digest` per tag). `image` is the newest tag's `<hub host>/<repository>:<tag>` (#323). `tags` lists every tag of the source with a row for the CVE (#350): `image` (`<hub host>/<repository>`), `image_tag`, `status` (`open`, `fixed` or `accepted`), `last_scan_at`, `fixed_in_version`, `newest_digest`; newest scan first, at most 100, with `tags_total` the count before the cap. `alias` is the other id of the CVE, its GHSA id, when a scanner reports the CVE under a GHSA id (migrations 0006 and 0007, #323, #337); `null` when none. |
| POST | `/api/v1/cves/:id/issue` | session (owner) | yes | Creates or reopens the GitHub issue for the CVE. `422` when the CVE is fixed on every tag. `409` when an open issue or an active acceptance exists. |
| POST | `/api/v1/cves/:id/accept` | session (owner) | yes | `{"reason","expires_at"}`; `reason` may be empty (max 1000 characters). Applies to the whole source. Does not close an open issue. |
| POST | `/api/v1/cves/:id/false-positive` | session (owner) | yes | Same body and answer as accept; stores the verdict with `kind = 'false_positive'`, comments on an open issue and never closes it. `409` while any verdict is active. Audited as `cve.false_positive`. The `acceptance` object carries `kind` (`accepted` or `false_positive`). |
| POST | `/api/v1/cves/:id/unaccept` | session (owner) | yes | Soft revoke of the active verdict of either kind. |
| POST | `/api/v1/cves/:id/review` | session (owner or admin) | yes | Clears the re-review flag (`changed_at`, `change_reason`) of the active acceptance. `204`. Audited as `cve.review`. The acceptance stays active. The CVE detail's `acceptance` carries `changed_at` and `change_reason` (both null when not changed). |

CVE list filters (spinoff section 10, decision 38, and [frontend.md](frontend.md), "CVE list control bar"):

- `namespace`: one value, the first segment of the source's repository, read by `services/cves.rs` (`parse_filters`). It replaces the removed Project filter. An empty value means no filter.
- `repository`: the source's `repository` with no hub host, the value `GET /api/v1/image-sources` returns (#323). `tag`: exact, newest-digest tags only. `source_id`: the source id, exact, read by the list handler. `q`: case-insensitive substring over the CVE id, the package, and the repository, with `%` and `_` literal. At most 100 characters, no control characters. `package`, `accepted`, `has_issue`, and `fix` are read too (see below). `q`'s searched columns are UNVERIFIED in this pass.
- `severity`: one or more of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN` (OR within the parameter).
- `status`: `open`, `fixed`, `accepted` (OR within). `open` excludes CVEs with an active acceptance, so Open and Accepted are disjoint.
- `has_issue`: `true` or `false`. Any other value is `400`.
- `fix`: `available`, `none` (OR within). Tests the `fixed_in_version` the Fixed in column shows.
- Parameters combine by AND. Bad values are `400 invalid_request`. `total` uses the same predicates as `items`.
- Harbor parameters `project`, `harbor_project`, `harbor_repository`, `mapping`, and `mapping_id` are not read (decision 38).

## Admin

All routes are `admin`.

| Method | Path | Built | Notes |
| --- | --- | --- | --- |
| GET | `/api/v1/admin/users` | yes | |
| POST | `/api/v1/admin/users` | yes | Local accounts only. Password 15 to 64 characters. |
| DELETE | `/api/v1/admin/users/:id` | yes | `409` for the last local admin, or for self. |
| PUT | `/api/v1/admin/users/:id/role` | yes | `409` for an OIDC user. |
| GET, PUT | `/api/v1/admin/oidc` | yes | The client secret is write-only. `422` when `oidc_only_users` is on while OIDC is incomplete. |
| GET, PUT | `/api/v1/admin/github-url` | yes | `422 settings.github_url_invalid` for a value that fails the rules in [security.md](security.md), "GitHub base URL". |
| GET | `/api/v1/admin/alert-channels` | yes | Config never returned. |
| POST | `/api/v1/admin/alert-channels` | yes | `422` on failure. |
| PUT | `/api/v1/admin/alert-channels/:id` | yes | |
| DELETE | `/api/v1/admin/users/:id/totp` | yes | Clears the user's TOTP and recovery codes. `204`, `404` for an unknown user. Audited as `user.totp_reset` with the user's id only (#341). |
| GET | `/api/v1/admin/audit-log` | yes | Filters `action`, `actor_user_id`. |
| GET | `/api/v1/admin/jobs` | yes | Housekeeping runs from `job_runs`. Filter `kind`. |
| GET | `/api/v1/admin/health` | yes | Spinoff target: per-hub reachability, the pinned scanner versions, the database build time per scanner, free disk of the store, and the caller's client IP and its source. The Harbor and robot fields are removed. Field shape UNVERIFIED. |
| POST | `/api/v1/admin/backup` | yes | `{"file","path"}`. Writes only to the configured backup directory. |
| GET | `/api/v1/admin/logs` | yes | Query `level` (minimum level), `q`. |
| GET, PUT | `/api/v1/admin/log-level` | yes | `info`, `debug`, or `trace`. A level above `info` reverts after 30 minutes. |

Restore and key re-encryption are CLI commands, not HTTP routes ([security.md](security.md)).

## Health

| Method | Path | Auth | Built | Notes |
| --- | --- | --- | --- | --- |
| GET | `/healthz` | public | yes | Process liveness only. Returns 200 without touching SQLite or any registry. Excluded from rate limits. |

## Not built and removed

- Removed (Harbor): `/api/v1/webhooks/harbor/*`, `/api/v1/project-webhooks*`, `/api/v1/mappings*`, `/api/v1/sync-jobs*` (now `/api/v1/jobs*`), `/api/v1/credentials/:id/harbor-*`, `/api/v1/credentials/:id/source-suggestion`, `/api/v1/pickers/hidden*`, and the Harbor pickers. These are absent from `backend/src/main.rs`.
- Not built: `/api/v1/credentials/:id/github-repositories` (listed above).
- Not built: a `namespace` filter on `/api/v1/cves` (listed above).
