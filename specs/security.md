# Security

Purpose: encryption, key handling, backup and restore, authentication, sessions, hardening, tenancy, and secret handling.

Decisions are marked `Decided (<date>)`. On 2026-11-03 the user delegated every remaining proposal; those decisions are marked `Decided (2026-11-03, delegated)`. `Verified (<date>)` marks a claim checked against the cited source on that date. `UNVERIFIED:` marks a claim that can only be checked against a live system or a later build.

## Encryption and keys

- `DOCKWARD_ENCRYPTION_KEY` is read from the environment and is required. The app refuses to start without it.
- No file fallback for the key.
- AES-256-GCM encrypts stored user credentials (GitHub PATs), source registry credentials (`source_credentials.encrypted_token`), OIDC client secrets, and alert SMTP and webhook secrets (spinoff section 12). The Harbor robot secrets and the webhook digests are removed with Harbor.
- Losing `DOCKWARD_ENCRYPTION_KEY` makes stored credentials unrecoverable. Operators must back it up separately.
- The credential encryption key, the session signing key, the backup key, and the CSRF key are all derived from `DOCKWARD_ENCRYPTION_KEY`. Decided (2026-11-03): the raw key is input key material only and is never used directly to encrypt or sign. See "Derived keys" below.

### Encryption key format

- Decided (2026-11-03, delegated): `DOCKWARD_ENCRYPTION_KEY` is the base64 encoding of exactly 32 random bytes. The app refuses to start if the value does not decode to exactly 32 bytes.
- Source: AES-256 uses a 256-bit key (FIPS 197, https://csrc.nist.gov/pubs/fips/197/final). The 32-byte length follows from that. Base64 is the encoding that `openssl rand -base64 32` already produces in [docs/SETUP.md](../docs/SETUP.md).

### Ciphertext format and key version

- Decided (2026-11-03, delegated): every stored ciphertext is the string `v<key_version>:` followed by `base64(nonce || ciphertext || tag)`. For v1 the stored value is `v1:` + base64(12-byte nonce || ciphertext || 16-byte tag).
- `key_version` is 1 in v1. The prefix exists so that a later key rotation can identify which key wrote each value without a schema change.
- Nonce: a fresh random 96-bit nonce for every encryption. Never reuse a nonce with the same key.
- Decided (2026-11-03): values are encrypted with the derived credential key (HKDF label `dockward/credentials-v1`), not with the raw `DOCKWARD_ENCRYPTION_KEY`.
- Decided (2026-11-03): each value is bound to where it is stored through GCM additional authenticated data (AAD). The AAD is the UTF-8 string `<table>:<column>:<row id>`, for example `user_credentials:encrypted_token:<id>`. For `system_config` the row id is the key, for example `system_config:value:oidc.client_secret_encrypted`. A ciphertext copied to another row, column, or table fails to decrypt. The AAD is not stored. It is rebuilt from the row on every read. Source: NIST SP 800-38D (https://csrc.nist.gov/pubs/sp/800/38/d/final), which defines the GCM additional authenticated data input.
- Source: NIST SP 800-38D, Recommendation for Block Cipher Modes of Operation: GCM (https://csrc.nist.gov/pubs/sp/800/38/d/final). It defines the GCM IV and authentication tag. Verified (2026-11-03) against the SP 800-38D PDF: section 5.2.1.1 recommends restricting IVs to 96 bits; section 5.2.1.2 lists the tag lengths 128, 120, 112, 104, and 96 bits (128 is the full 16-byte tag); section 8.2.2 defines the random (RBG-based) IV construction; and section 8.3 limits a key to 2^32 encryptions when IVs are random. Decided (2026-11-03, delegated): that limit is far above dockward's expected volume, and a key rotation (see "Key rotation") starts a new count.
- The 12-byte nonce and 16-byte tag are the GCM sizes from NIST SP 800-38D. They are not chosen values.

### Derived keys

- Decided (2026-11-03, delegated): the session signing key, the backup key, and the CSRF key are derived from `DOCKWARD_ENCRYPTION_KEY` with HKDF-SHA256 (RFC 5869).
  - Session: info label `dockward/session-v1`, output length 32 bytes (HS256 key).
  - Backup: info label `dockward/backup-v1`, output length 32 bytes (AES-256 key).
  - CSRF: info label `dockward/csrf-v1`, output length 32 bytes (HMAC-SHA256 key). Decided (2026-11-03).
  - Credentials: info label `dockward/credentials-v1`, output length 32 bytes (AES-256-GCM key for every stored ciphertext). Decided (2026-11-03).
- Use no salt (RFC 5869 section 3.1 allows an absent salt). The input key material is already 32 random bytes, so the salt is not needed for extraction.
- Source: RFC 5869, HKDF (https://www.rfc-editor.org/rfc/rfc5869). Section 3.2 describes the `info` input for domain separation, which is why each derived key has its own label.
- The HS256 key length follows RFC 7518 section 3.2 ("a key of the same size as the hash output", 256 bits for SHA-256).

### Key rotation

- Decided (2026-11-03): key re-encryption is a CLI command only. It is not an HTTP route and is not in the admin UI. Keys are never typed into the browser.
- The command runs offline with the app stopped. Both keys are read from the environment for that one run: `DOCKWARD_OLD_ENCRYPTION_KEY` (the key that wrote the current values) and `DOCKWARD_ENCRYPTION_KEY` (the new key).
- The command decrypts every stored ciphertext with the credential key derived from the old key and re-encrypts it with the credential key derived from the new key. The AAD of each value is unchanged. It writes `v1:` values, and the key version does not change until a v2 format exists. Every encrypted column is covered, including `source_credentials.encrypted_token`, `user_credentials.encrypted_token`, `alert_channels.config_encrypted`, and the encrypted `system_config` values (spinoff section 12; a test enumerates them).
- The rewrite runs in a single transaction. If any row fails to decrypt, the whole transaction rolls back and no row changes.
- After the rewrite, the command appends a `key.rotate` audit row, the same way restore does, with actor `cli`. The row holds the count of rows rewritten and no key material.
- Key values are never logged, printed, or traced.

## Backup and restore

- Decided (2026-11-03): backup is created from Settings > Backup and restore in the admin UI (`POST /api/v1/admin/backup`). The admin UI does not restore.
- Backup: the backup writes a consistent copy of the database with `VACUUM INTO` (see the source note below).
- Decided (2026-11-03, delegated): the backup file is encrypted with AES-256-GCM using the derived backup key and the ciphertext format above. The file begins with a plain header `HGBK1` (5 bytes, ASCII) that identifies the format, and is followed by the nonce, ciphertext, and tag. Decided (2026-11-03, delegated): the header bytes are the GCM AAD, so a changed header fails verification. A backup can be restored only with the `DOCKWARD_ENCRYPTION_KEY` that created it. After a key rotation, older backups need the old key, so operators keep the old key for as long as they keep backups made with it.
- Decided (2026-11-03, delegated): restore verifies the GCM authentication tag over the whole file before it writes anything. The live database is replaced only after the tag verifies. A file that fails verification is rejected and the live database is untouched.
- Source for the authenticated-encryption behaviour: NIST SP 800-38D (https://csrc.nist.gov/pubs/sp/800/38/d/final). Decided (2026-11-03, delegated): the consistent copy is made with `VACUUM INTO '<temporary file>'`, which SQLite documents as producing "a consistent snapshot" of the database (https://www.sqlite.org/lang_vacuum.html, verified (2026-11-03)). SQLite's online backup API is not used, because SQLx does not expose it (verified (2026-11-03): the SQLx source has no `sqlite3_backup_init` binding). The temporary file is written in `DOCKWARD_DATA_DIR`, next to the live database, encrypted into `DOCKWARD_BACKUP_DIR`, then deleted.
- Default location: `/data/backups`. Operators may set another path with `DOCKWARD_BACKUP_DIR`.
- Decided (2026-11-09, user, issue #273, decisions 1 and 2): dockward creates the configured backup directory at startup, for both the default and an operator-set `DOCKWARD_BACKUP_DIR`, if it does not exist. It is created with mode 0700 and owned by the process user (65532 in the image). If it exists and is not writable, the existing clear error is kept and the directory's permissions are not changed. A directory that exists and is writable is left alone. If it cannot be created, startup fails with a clear error.
- The command writes only to that path.
- If the directory is missing or not writable, the command fails with a clear error. The error is shown in the admin UI and logs. It never falls back to another location.
- Restore: Decided (2026-11-03). Restore is an offline command-line subcommand, for example `dockward restore <file>`, run with the app stopped. It is not an HTTP route and not in the admin UI. Run it with the same `DOCKWARD_ENCRYPTION_KEY` that created the backup.
- Decided (2026-11-03): after the offline restore replaces the database, the command appends one `restore.run` audit row to the restored database. `details` holds the backup file name, the backup `created_at`, and the actor, recorded as `cli` (the operator running the command). See "Audit action vocabulary" in [database.md](database.md).
- Restore steps are documented in `docs/SETUP.md`.

## Authentication

- **Passwords:** Decided (2026-11-03, delegated): Argon2id with memory 19456 KiB (19 MiB), 2 iterations, and parallelism 1.
  - Source: OWASP Password Storage Cheat Sheet, which recommends "Argon2id with a minimum configuration of 19 MiB of memory, an iteration count of 2, and 1 degree of parallelism" (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
  - Source: RFC 9106, Argon2 (https://www.rfc-editor.org/rfc/rfc9106). Section 4 covers parameter choice.
  - The salt is 16 bytes (128 bits) from a CSPRNG. RFC 9106 section 4 (Parameter Choice) recommends a 128-bit salt, and the OWASP cheat sheet requires a unique salt per password.
  - Store the output as a PHC string in `users.password_hash`.
- **Password length:** Decided (2026-11-03): minimum 15 characters. Maximum accepted length 64 characters, which is the smallest maximum the cited guidance allows (it says a maximum should be at least 64).
  - Source: OWASP Authentication Cheat Sheet, which says passwords shorter than 15 characters are weak when MFA is not enabled (https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
  - Source for the maximum: OWASP Authentication Cheat Sheet, which cites NIST SP 800-63B for a maximum of "at least 64 characters" (https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
  - The rule applies everywhere a local password is set: setup, change-password, and admin-created local users (`POST /api/v1/admin/users`).
  - Violations return `400` with code `password_too_short` on those routes in [api.md](api.md).
  - No composition rules. OWASP says there should be "no requirement for upper or lower case or numbers or special characters."
- **Two-factor sign-in (TOTP):** Decided (2026-11-12, #341): optional for local accounts only. OIDC sign-in and accounts are unchanged.
  - Decided (2026-11-12, user, #341): the 15-character minimum stays for every local account, with or without TOTP. The OWASP wording above is about accounts without MFA, but the rule is kept as one rule everywhere (setup, change-password, admin-created users), so nothing about the password changes when TOTP is turned on.
  - RFC 6238 with HMAC-SHA1, 6 digits, 30-second steps, one step of drift either side, because that is what every authenticator app supports. Source: RFC 6238 and RFC 4226. The 20-byte secret comes from the OS CSPRNG and is shown once as base32 and an `otpauth://` URI.
  - The secret is sealed like the other stored secrets: `v1:` AES-256-GCM under the credentials key, AAD `totp_secrets:secret_encrypted:<user_id>`. No new HKDF label is needed, because the AAD separates it from every other ciphertext. Key rotation re-encrypts it (`ENCRYPTED_COLUMNS`).
  - Enrolment stores the secret disabled. A valid current code enables it and returns 10 recovery codes once. Recovery codes are stored as Argon2id hashes and each works once.
  - Sign-in: a correct password for a user with TOTP on returns a challenge cookie (`__Host-dockward_totp`, HMAC-signed with the session key under its own header type, 5 minutes) and no session. `POST /api/v1/auth/totp/verify` issues the session after a valid code. Every failure there is the same `401 invalid_credentials` as a wrong password.
  - Replay: `totp_last_step` holds the newest accepted step. A code for that step or an earlier one is refused. One conditional `UPDATE` moves it, so two requests with one code cannot both win.
  - Lockout: 5 wrong codes per account in 15 minutes, in memory. The fifth writes `user.totp_lockout` (the failure count only), and the account's code step answers `429` until the window ends. This lockout covers only the code step, after the password was right, so it cannot block break-glass sign-in by someone who only knows a username.
  - Disable needs a valid current code. An admin can clear any user's TOTP (`user.totp_reset`).
- **Failed-login throttling:** Decided (2026-11-03): there is no hard account lockout. The login route is public, so a lockout would let anyone who knows an admin's username block admin break-glass access.
  - Progressive delay, kept per (account, client IP) pair, so failures from one address do not delay the real user at another address. Decided (2026-11-03, delegated) values: after 5 consecutive failures for a pair, each further attempt must wait 2^(n-5) seconds after the previous failure (1 s, 2 s, 4 s, and so on), capped at 60 seconds. A successful login resets the counter. An attempt inside the wait returns the same `401 invalid_credentials` without checking the password. Decided (2026-11-03, delegated): no external source for the numbers; tune in deployment.
  - Per client IP: the login rate limit under "Hardening". The client IP is derived as described under "Client IP".
  - Source: OWASP Authentication Cheat Sheet, "Account Lockout" (https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), which warns that lockout can be abused for denial of service. Verified (2026-11-03) in the cheat sheet source: it describes an exponential lockout that starts at about one second and doubles after each failure, and warns that lockout can be used to deny service to other users.
- **Equal-time failures:** Decided (2026-11-03): a login for an unknown username, for an OIDC-only user, or for a regular local user while local login is restricted still runs an Argon2id verification against a fixed dummy PHC hash with the same parameters. The response time then does not reveal whether the account exists. Source: OWASP Authentication Cheat Sheet, authentication and error messages (same URL).
- **First-run setup:** the first local account created becomes `Admin`.
  - Decided (2026-11-03): the setup route is closed permanently once the first account exists. It is allowed only while the `users` table is empty. The insert runs in a single transaction that inserts only if the table is empty, so concurrent setup requests cannot create two first admins.
  - Decided (2026-11-03): local accounts are created by an admin in Settings > Users. OIDC accounts are created just-in-time on the user's first successful OIDC login, with no admin pre-creation.
  - The setup page design needs user approval before build.
- **OIDC:** configured in the Admin UI. Settings are the `oidc.*` keys in [database.md](database.md). Client secret encrypted (`is_encrypted = 1`).
  - Decided (2026-11-03, delegated): the issuer URL must be HTTPS. Source: OpenID Connect Discovery 1.0 (https://openid.net/specs/openid-connect-discovery-1_0.html), which specifies the https scheme for the issuer. Verified (2026-11-03): section 3, OpenID Provider Metadata, `issuer`: "URL using the https scheme with no query or fragment components".
  - Decided (2026-11-03, delegated): the OIDC user is identified by `(oidc_issuer, oidc_subject)`, not by email. Source: OpenID Connect Core 1.0, section 2, `sub` (locally unique and never reassigned within the issuer).
  - Decided (2026-11-03, delegated): the flow uses the authorization code grant with PKCE (S256). Source: RFC 6749 (https://www.rfc-editor.org/rfc/rfc6749), RFC 7636 (PKCE, https://www.rfc-editor.org/rfc/rfc7636). The `state` value is verified on callback to prevent CSRF, per RFC 6749 section 10.12 (Cross-Site Request Forgery, confirmed in the RFC table of contents).
  - Decided (2026-11-03): the authorization request also carries a random `nonce`. The `state`, the PKCE verifier, and the `nonce` are kept in the short-lived `__Host-dockward_oidc` cookie (see "Sessions"). The ID token's `nonce` claim must equal it, or the callback fails with 401. Source: OpenID Connect Core 1.0 (https://openid.net/specs/openid-connect-core-1_0.html), the `nonce` request parameter and ID token validation. Verified (2026-11-03): sections 3.1.2.1 (Authentication Request, `nonce`) and 3.1.3.7 (ID Token Validation).
  - Role on each OIDC login: the role is re-read from the configured group claim (`oidc.role_claim`) at each login. The group value is matched against `oidc.admin_group` and `oidc.user_group`. A user with neither group cannot sign in.
  - Decided (2026-11-03): for OIDC users the group claim is the only source of the role. An admin cannot change an OIDC user's role in the UI or the API. `PUT /api/v1/admin/users/:id/role` returns `409 conflict` for an OIDC user. Role changes for OIDC users are made in the identity provider and apply at that user's next login.
- **Local session role:** Decided: a local session's role is looked up from `users.role` on each request. A demotion takes effect on the next request, not at the next login. This matches the rule that an admin is revoked when demoted within the 8-hour session lifetime.
- **Local login:** Decided (2026-11-03): admins can always sign in with a local password (break-glass), including after OIDC is configured. Regular users with a local account can sign in locally unless the "OIDC only for regular users" toggle in Settings > OIDC is on. While the toggle is on, a `user` login with a local password gets `401 invalid_credentials`. The toggle never affects admins.
  - Decided (2026-11-03, delegated): the toggle is stored as the `system_config` key `auth.oidc_only_users` (see [database.md](database.md)). It can be turned on only while the OIDC settings are complete; otherwise `PUT /api/v1/admin/oidc` returns 422.
  - Decided (2026-11-03): OIDC settings and break-glass are managed in the Admin UI, Settings > OIDC. Settings are stored in `system_config` (the `oidc.*` keys in [database.md](database.md)). The client secret is encrypted with AES-256-GCM (`is_encrypted = 1`). The toggle on the same screen restricts regular users to OIDC sign-in; admin break-glass login is always available. Every change is audited as `oidc.config_change`, with `details` that never include the secret. Route: `GET` and `PUT /api/v1/admin/oidc` ([api.md](api.md)). Break-glass local login stays available to admins at all times, including after OIDC is configured. The toggle restricts only regular users to OIDC sign-in and never disables admin break-glass.
  - Decided (2026-11-03): OIDC is configured only when issuer, client ID, client secret, role claim, and at least one group (admin or user) are all set. Settings missing any of these leave OIDC unconfigured: start and callback return 404, and the toggle cannot be turned on.
  - Decided (2026-11-03): clearing an optional OIDC setting deletes its `system_config` row. No empty values are stored.
  - Decided (2026-11-03): the `user.role_change` audit entry written at OIDC login names the user as actor, with `details.source` set to `"oidc"`.
  - Decided (2026-11-03, delegated, #49): a sign-in refused for having no allowed group ends that user's existing sessions. For an existing user, the callback bumps `token_version` and writes `user.role_change` (`to: null`, `source: "oidc"`) in one transaction, so the old session fails with `401` at the next request. A user who does not exist has no session, so no row is created.
  - Decided (2026-11-03, delegated, #49): once OIDC is configured, every callback outcome is `302`. Success goes to `/`. A failure, or the provider's `error` parameter, goes to `/?oidc_error=<code>`, where `<code>` is the `AppError` code or `provider_error`. Provider text never goes in the URL. The `__Host-dockward_oidc` cookie is cleared on every outcome. While OIDC is not configured, the callback returns `404`.
  - Decided (2026-11-03): the issuer is compared as an exact string against the configured value, both for the discovery `issuer` and the ID token `iss`. No URL normalisation (for example, no trailing-slash trimming).
  - Decided (2026-11-03): a JWKS refresh for an unknown `kid` happens at most once per minute (`JWKS_REFRESH_MIN_INTERVAL = 60s`).
- Roles: `Admin` (system config, user management, global logs, read-only view of all tenants) and `User` (own credentials, own sources, images, and jobs).

## Sessions

- Decided (2026-11-03, delegated): the session is a signed JWT in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie. The base cookie names are Decided (2026-11-03, delegated); no external source applies.
- Decided (2026-11-03): every dockward cookie uses the `__Host-` prefix. It is therefore `Secure`, has `Path=/`, and has no `Domain` attribute, and the browser rejects a cookie of that name set by a sibling subdomain. Names: `__Host-dockward_session` (session), `__Host-dockward_csrf` (CSRF), and `__Host-dockward_oidc` (OIDC `state`, PKCE verifier, and `nonce`; lifetime 10 minutes, Decided 2026-11-03, delegated). Source: RFC 6265bis, draft 22, section 4.1.3.2, "The __Host- Prefix" (https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/, verified (2026-11-03)). Development over `http://localhost` works: MDN's `Set-Cookie` reference states that the `https:` requirement of `Secure` is ignored on localhost (verified (2026-11-03)).
- Signing: HS256 with the derived session key. Source: RFC 7519 (https://www.rfc-editor.org/rfc/rfc7519). Section 4.1.4 defines `exp`. Section 4.1.7 defines `jti`.
- Claims: `sub` (user id), `role` (informational only, see "Local session role"), `iat`, `exp`, `jti`, and `ver` (the user's `users.token_version` when the token was issued).
- Validation on every request: verify the signature, the `exp` claim, `alg` equal to `HS256`, and `ver` equal to the user's current `users.token_version` (read in the same per-request user lookup as the role). Reject `alg: none`. Source: RFC 7519 section 6 (https://www.rfc-editor.org/rfc/rfc7519). RFC 8725 section 3.1, "Perform Algorithm Verification" (verified (2026-11-03)), requires the verifier to accept only an allowed set of algorithms and to use each key with exactly one algorithm. The derived session key is used only for HS256.
- Expiry: 8 hours. `exp` is `iat` + 8 hours. The 8-hour lifetime is a user decision.
- Logout clears the cookie.
- Decided (2026-11-03): revocation is per user through `users.token_version`. `POST /api/v1/auth/logout-all` and a password change both increment it, which invalidates every existing session of that user. The session that changed the password receives a fresh cookie. Deleting a user removes the row, so that user's sessions fail the per-request lookup.
- A single logout only clears the browser cookie. A copied JWT stays valid until `exp` or until the next `token_version` change. Decided (2026-11-03, delegated): no per-session `jti` denylist in v1.
- An admin who is demoted keeps a valid JWT, but the request's role comes from the database (see "Local session role"), so the demotion takes effect immediately for authorization.
- Source for cookie attributes: OWASP Session Management Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), which covers the `Secure` and `HttpOnly` attributes. Verified (2026-11-03): the cheat sheet's "SameSite Attribute" section describes `Strict` and `Lax`. `Lax` is used because the OIDC callback is a top-level cross-site navigation from the identity provider and must carry the `__Host-dockward_oidc` cookie; `Strict` would drop it.

## Hardening

- Decided (2026-11-03, delegated): rate limits on the login endpoint: 10 attempts per minute per client IP. Decided (2026-11-03, delegated): no external standard; tune in deployment. The client IP is derived as in "Client IP" below.
- Client IP: Decided (2026-11-03): the client IP is the TCP peer address, unless the peer is inside `DOCKWARD_TRUSTED_PROXIES` (see [deployment.md](deployment.md)). In that case the client IP is the rightmost address in `X-Forwarded-For` that is not itself a trusted proxy. With the default empty list, `X-Forwarded-For` is ignored. Decided (2026-11-03, delegated): `CF-Connecting-IP` is not read; Traefik passes the client address on in `X-Forwarded-For`. Source: MDN, `X-Forwarded-For`, security and privacy concerns (https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For). Verified (2026-11-03): MDN states that any security-related use, such as rate limiting, "must only use IP addresses added by a trusted proxy". Verified (2026-11-03), header chain in the reference setup (Cloudflare edge, cloudflared, Traefik, dockward):
  - The Cloudflare edge sends `X-Forwarded-For` with the visitor IP. If the visitor already sent the header, the edge appends the address that connected to it. Either way, the rightmost entry from the edge is the address that connected to Cloudflare. Source: Cloudflare docs, HTTP request headers (https://developers.cloudflare.com/fundamentals/reference/http-headers/).
  - cloudflared does not change `X-Forwarded-For`. It only sets `X-Forwarded-Host` when an origin Host header is configured (`ingress/origin_proxy.go` in cloudflare/cloudflared).
  - Traefik deletes incoming `X-Forwarded-*` headers when the peer is not in the entry point's `forwardedHeaders.trustedIPs`, and then appends the peer address (`pkg/middlewares/forwardedheaders/forwarded_header.go` in traefik/traefik; Traefik docs, EntryPoints, `forwardedHeaders.trustedIPs`). With no trusted IPs set, dockward would see only cloudflared's address, and all visitors would share one rate-limit bucket.
  - Decided (2026-11-03, delegated): the reference setup requires two settings. The Traefik entry point trusts cloudflared's source address (`forwardedHeaders.trustedIPs`). `DOCKWARD_TRUSTED_PROXIES` lists Traefik's address and cloudflared's source address. dockward then receives `X-Forwarded-For: [visitor-sent entries,] <visitor IP>, <cloudflared IP>` from peer Traefik, and the rightmost entry that is not a trusted proxy is the visitor IP. Steps: [deployment.md](deployment.md), "Client IP behind Cloudflare and Traefik".
  - Decided (2026-11-03), as implemented in `backend/src/api/hardening.rs`: entries that do not parse as an IP address are skipped. If the header is missing, or every usable entry is a trusted proxy, the client IP is the TCP peer address.
  - The addresses themselves depend on the host, because Docker assigns network subnets dynamically. The operator confirms them with the client IP check on the Health page ([api.md](api.md), "Health"). The live smoke test records them once.
- Removed (spinoff, decision 1): the webhook endpoint rate limits. There is no webhook endpoint.
- Decided (2026-11-03): every route that calls an outbound service or starts work declares its limit ([api.md](api.md), "Rate limits"). Routes without a declared limit are not rate limited, by decision.
- Decided (2026-11-05, user, #131, carried over): one manual scan of a source per 5 minutes, in memory (`POST /api/v1/image-sources/:id/scan`). Over the limit: `429` with `Retry-After`.
- Decided (2026-11-04, #50): every response under `/api/` carries `Cache-Control: no-store`. Those responses can hold one-time secrets (the mapping create and rotate responses) and authenticated data. Source: OWASP REST Security Cheat Sheet, "Security headers" (https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html).
- Decided (2026-11-03, delegated): rate-limited responses return 429 with a `Retry-After` header. Source: RFC 6585 section 4 (429 Too Many Requests, https://www.rfc-editor.org/rfc/rfc6585), and RFC 9110 section 10.2.3 (Retry-After, https://www.rfc-editor.org/rfc/rfc9110).
- Removed (spinoff, decision 1): the 64 KiB webhook body cap. There is no webhook endpoint.
- CSRF: Decided (2026-11-03): signed double-submit cookie. The cookie `__Host-dockward_csrf` holds a token. The client must send the same value in the `X-CSRF-Token` header on every `POST`, `PUT`, `PATCH`, and `DELETE` under `/api`. Exempt: the login and setup endpoints (no session yet), which use the same-origin check below instead. Missing or mismatched token returns 403. The webhook exemption is removed with the webhook (`backend/src/auth/csrf.rs`, which still names it; see the CONFLICT at the end of this file).
  - Source: OWASP CSRF Prevention Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), which describes the Double Submit Cookie pattern, and recommends a custom request header and verifying the origin.
  - The OWASP sheet says the signed double-submit variant is stronger. Decided (2026-11-03): the token is HMAC-SHA256 signed with the CSRF key derived via HKDF label `dockward/csrf-v1` (see "Derived keys"). Decided (2026-11-03): the CSRF token is bound only to the signed cookie value (HMAC over the cookie with the CSRF key). The session `jti` is not part of the CSRF binding.
- `SameSite=Lax` alone is not sufficient.
- Login CSRF: Decided (2026-11-03): `POST /api/v1/auth/login` and `POST /api/v1/auth/setup` require a same-origin request. The `Origin` header must equal the origin of `DOCKWARD_PUBLIC_URL`. Decided (2026-11-04, #50): the startup value is stored in canonical origin form, with a lowercase host and the default port removed (`:443` on `https`, `:80` on `http`). For example, `https://Harborgate.Example.com:443/` is stored as `https://harborgate.example.com`. Browsers send `Origin` in this form, so the comparison is exact after normalisation. When `Origin` is absent, `Sec-Fetch-Site` must be `same-origin`. When neither header is present, or a value does not match, the response is `403 csrf_invalid`. This stops another site from signing a victim in to an attacker's account. Source: OWASP CSRF Prevention Cheat Sheet, login CSRF and verifying origin with standard headers (same URL as above); W3C Fetch Metadata Request Headers (https://www.w3.org/TR/fetch-metadata/).
- Security headers: Decided (2026-11-03): the backend sets these headers on every response, so they apply behind any proxy:
  - `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, plus (Decided 2026-11-03, delegated) `base-uri 'none'; form-action 'self'; object-src 'none'`.
  - `X-Content-Type-Options: nosniff`.
  - `Referrer-Policy: no-referrer`.
  - `Strict-Transport-Security` is set by Traefik, not by the app, because the app cannot tell whether TLS ends in front of it.
  - Source: OWASP HTTP Headers Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).
  - Verified (2026-11-03), styles under `default-src 'self'`:
    - The production build links CSS as files. The scaffold's `vite build` (Vite 8, `@tailwindcss/vite` 4) emits `<link rel="stylesheet" href="/assets/index-<hash>.css">` and an external module script, with no inline `<style>`, inline script, or `data:` URI.
    - React applies the `style` prop with CSSOM property setters (`style[name] = value`, `style.setProperty`), in `setValueForStyle` in react-dom 19.3.1 `react-dom-client`. Recharts 3.10.1 measures text with `Object.assign(span.style, ...)` (`es6/util/DOMUtils.js`). CSP does not block CSSOM property setters, only the `style` attribute in markup and `setAttribute("style")` and `cssText` (MDN, CSP `style-src`, https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/style-src). Neither library needs `'unsafe-inline'`.
    - Radix UI does inject `<style>` elements, and `'self'` blocks them. The Select viewport (`@radix-ui/react-select` 2.4.1) and the ScrollArea viewport (`@radix-ui/react-scroll-area` 1.4.0) take a `nonce` prop. Dialog's scroll lock comes from `react-remove-scroll-bar` through `react-style-singleton` 2.2.3, which reads its nonce from `get-nonce`.
    - Vite inlines small assets as `data:` URIs by default, and `default-src 'self'` blocks those (Vite docs, Features, "Content Security Policy (CSP)").
  - Decided (2026-11-03, delegated): the HTML policy is `default-src 'self'; style-src 'self' 'nonce-<n>'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'`. `<n>` is 16 random bytes, base64-encoded, new for every HTML response. There is no `'unsafe-inline'` and no `'unsafe-eval'`. Scripts need no nonce, because every script is an external file.
    - Vite `html.cspNonce` is set to a fixed placeholder. Vite then adds `nonce` to its tags and emits `<meta property="csp-nonce" nonce="...">`. On every HTML response the backend replaces the placeholder in the embedded `index.html` and sends the same value in the CSP header. HTML responses carry `Cache-Control: no-store`. Hashed assets under `/assets/` stay cacheable.
    - The frontend reads the nonce from the meta element's `nonce` property, not `getAttribute`, because browsers hide the attribute value. It calls `setNonce` from `get-nonce` before the first render, and passes `nonce` to the Radix Select and ScrollArea viewports.
    - `build.assetsInlineLimit` is `0`, so the build has no `data:` URIs.
    - API and other non-HTML responses carry the policy without a nonce source.
    - Tests: a backend test checks that each HTML response has a fresh nonce, that the header and `index.html` carry the same value, and that no placeholder is left. The live smoke test opens each page and fails on any `securitypolicyviolation` event ([testing-and-ci.md](testing-and-ci.md)).

## Tenancy

- Users see only their own credentials, sources, images, findings, and jobs.
- Admins may view all of it, read-only.
- Admins cannot change another user's credentials or sources.
- Decided (2026-11-03, carried over): the first operational exception to read-only admin access is retry. An admin may retry failed jobs of any tenant (`POST /api/v1/jobs/:id/retry`). Retry only re-queues work and changes no source or credential.
- Decided (2026-11-05, user, #131, carried over): the second operational exception is starting a scan of a source. An admin may run discovery for any tenant's source (`POST /api/v1/image-sources/:id/scan`). It uses the source's own registry credential on the server, and no credential value is shown to the admin. It only queues work.
- Decided (2026-11-08, user, #243, carried over): the third operational exception is purging failed jobs (`POST /api/v1/jobs/purge-failed` with `scope=all`). The owner purges their own sources' failed jobs; an admin may purge any tenant's. A purge deletes job rows only and changes no source, credential, finding, report, issue, or alert. Audit: one `sync_job.purge` entry per purge that deletes a row, with the actor, the scope (`own` or `all`), and the count. `details` hold no secret, job payload, error text, or id list.
- A credential may be referenced only by a source owned by the same user. The application checks this on write.
- Registry credentials are per source (spinoff decision 35). No hub-level or namespace-level credential exists.
- Removed (spinoff, decision 1): the Harbor picker rules, the Harbor scanner rules, and the Harbor robot rules. There is no Harbor client.

## Secrets in logs

- GitHub PATs, registry tokens, bearer tokens from a registry token service, AES keys, and the `Authorization` and `Www-Authenticate` values are never printed in logs, traces, or Server-Sent Events streams (spinoff section 12).
- Removed (spinoff, decision 1): the webhook URL token and the webhook auth header value. There is no webhook.
- Audit `details` never contain tokens or key material.
- Error messages never include a secret value. Source: CLAUDE.md non-negotiable rules.

### Application log

Decided (2026-11-05, user, #136). The application log is the `tracing` output used for diagnosis. Admins can read the recent part of it and change its level in the web interface.

- The rules in "Secrets in logs" apply at every level (`info`, `debug`, `trace`) and to the in-memory buffer the admin reads. No level may log a token, a key, a webhook URL token, an auth header value, a request or response body, or a request header.
- Fields whose names contain one of the audit secret fragments (`token`, `secret`, `password`, `cookie`, `authorization`, `private`, `credential_value`) or that name key material (`key`, `*_key`, `key_*`) are dropped from a buffered line, whatever their value. The audit `details` check uses the same list (`services/audit.rs`).
- Storage: an in-memory ring buffer of at most 500 lines. A line longer than 1000 characters is cut, with a marker. The buffer is lost on restart. No database table holds log lines.
- Level: the admin can set the global level to `info`, `debug`, or `trace`. There are no per-module filters. `RUST_LOG` is ignored; every start uses `info`. `debug` and `trace` apply to dockward's own code only. Dependency crates (such as `hyper`, `h2`, `rustls`, `sqlx`, `reqwest`) stay at `info` or higher at every level.
- Automatic revert: a level above `info` reverts to `info` 30 minutes after it was set. A later change restarts the timer. A restart also returns to `info`.
- Audit: every level change, by an admin or by the automatic revert, writes `log.level_change` with `details` `{"old","new"}`. The automatic revert uses the actor `system`.
- At `debug`, each outbound registry and GitHub request logs its method, its URL path (no query string, no userinfo, no host credentials) and the response status code. OIDC and alert webhook URLs are not logged, because they can carry tokens.
- Access: admin only, for reading the log and for changing the level. A regular user gets `403`; no session gets `401`. Log lines can name any tenant's mapping, so a regular user never sees them.
- Separation: log lines are never written to `audit_log`, and audit rows are never shown as log lines. The audit log is the record of who did what; the application log is for diagnosis only.

## Dependency audit

- Decided (2026-11-09, user, #263): CI ignores advisory RUSTSEC-2026-0459 in `cargo audit` (`backend/.cargo/audit.toml`) and `cargo deny` (`backend/deny.toml`). No released SQLx allows `libsqlite3-sys` 0.39 or newer yet, and dockward's local SQLite file is not writable by untrusted parties. Removal condition: remove both entries when SQLx ships a release that allows `libsqlite3-sys` 0.39 or newer; check at each Renovate update.

## Outbound HTTP (SSRF)

- Decided (2026-11-03, delegated): every hub host and every redirect hop must use HTTPS. Plain HTTP is refused unless the hub is named in `DOCKWARD_ALLOW_PRIVATE_REGISTRIES` (spinoff decision 14).
- Decided (2026-11-03, delegated): every resolved address of a hub host, and of every redirect hop, must not be in loopback, link-local, or private ranges, unless the operator sets `DOCKWARD_ALLOW_PRIVATE_HARBOR=true`. The default is `false`. Harbor is removed in 0.2.0 and no service reads this variable; it is an open item in [integrations.md](integrations.md) (remove or keep).  - Blocked by default: `127.0.0.0/8`, `::1/128`, `169.254.0.0/16` (includes the cloud metadata address `169.254.169.254`), `fe80::/10`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `0.0.0.0/8`, and multicast `224.0.0.0/4`, `ff00::/8`. Also blocked: shared address space `100.64.0.0/10` (RFC 6598, used by CGNAT and Tailscale), `192.0.0.0/24` (RFC 6890, IETF protocol assignments), `198.18.0.0/15` (RFC 2544, benchmarking), reserved `240.0.0.0/4` (RFC 1112, includes `255.255.255.255`), local-use NAT64 `64:ff9b:1::/48` (RFC 8215, blocked whatever it embeds). NAT64 `64:ff9b::/96` (RFC 6052) and 6to4 `2002::/16` (RFC 3056) are judged by the IPv4 address they embed, so `64:ff9b::808:808` is allowed and `64:ff9b::7f00:1` is blocked.
  - Source: OWASP SSRF Prevention Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), "Deny-list" table, and its advice to validate resolved IPs. The deny-list is a last resort. The sheet prefers allow-lists.
  - The check applies to every resolved address (IPv4 and IPv6) and must be repeated when DNS changes, to prevent DNS rebinding. Source: the same OWASP cheat sheet, on DNS rebinding.
  - Repository and tag names are validated before a request is made (Decided 2026-11-04, #50). A name splits on `/`, and each component is lowercase ASCII alphanumerics separated by single `.`, `_`, or `-`. The project has no `/`. The whole name is 1 to 255 bytes. A name outside this rule is refused with `422`. Every name segment is percent-encoded, and the repository's components are joined with `%252F`, so `?`, `#`, and `%` never change the request path.
  - Redirects: GitHub requests are not followed. Registry redirects are followed with a check on every hop (spinoff decision 12). Source: the OWASP cheat sheet, which says to disable redirects in the HTTP client for untrusted targets.
- Private registries are a real case. `DOCKWARD_ALLOW_PRIVATE_REGISTRIES` lists the hub hosts that may use plain HTTP and private addresses (spinoff decision 14). Off by default, environment-only, and applies to named hubs only.
- Scope: Decided (2026-11-03): the rules in this section (HTTPS only, the resolved-address check, re-checking on DNS change, no redirects) apply to every outbound URL that an admin or user enters:
  - every hub host and its pull endpoint (spinoff section 12);
  - the OIDC issuer URL and every endpoint taken from its discovery document (authorization, token, JWKS, userinfo);
  - alert webhook URLs. The SMTP host gets the same address check.
  - Each class has its own environment-only opt-out, default `false`: `DOCKWARD_ALLOW_PRIVATE_REGISTRIES` (hub hosts), `DOCKWARD_ALLOW_PRIVATE_OIDC`, and `DOCKWARD_ALLOW_PRIVATE_ALERTS`. The last two names are Decided (2026-11-03, delegated).
  - GitHub requests go only to the configured API base URL. The default is the fixed host `api.github.com`. An admin may set a custom one (GitHub Enterprise Server); see "GitHub base URL" below.

- Advisory lookups (Decided 2026-11-13, user, #379): the scan step calls two fixed public hosts, `api.osv.dev` and `api.github.com`, to learn the CVE id behind a GHSA or GO id ([integrations.md](integrations.md), "Advisory lookup"). They use the guarded client with the class `Advisory`: HTTPS only, no redirects, the resolved-address check, no opt-out. The request is a `GET` with the advisory id in the path and no token or other data. The GitHub advisory call never carries a credential and ignores the configured GitHub base URL.
- Scanner release check (Decided 2026-11-14, user, #390): a daily background task calls the fixed host `api.github.com` for the latest Trivy and Grype release ([integrations.md](integrations.md), "Upstream release check"). It uses the guarded client with the class `ScannerRelease`: HTTPS only, no redirects, the resolved-address check, no opt-out, and any host but `api.github.com` is refused before a request is built. The request is a `GET` with no token or other data, and the configured GitHub base URL is not used.

## GitHub base URL

- Decided (2026-11-06, user, #184): the custom GitHub base URL is an instance setting, one value for the whole instance, set by the admin. Empty means `https://api.github.com` (API) and `https://github.com` (web). See [integrations.md](integrations.md), "GitHub base URL".
- Validation, API base URL (Decided 2026-11-06, user, #184): a custom value must be `https`, have a host, and contain no userinfo (`user:pass@`), no port, no query, and no fragment. A path is allowed (for example `/api/v3` for GitHub Enterprise Server, or the `api.SUBDOMAIN.ghe.com` form for GHE.com with no path). The path is used only as a prefix for every GitHub REST path. It must not contain `..`, `//`, or an encoded slash (`%2F`, `%2f`, `%5C`, `%5c`) that changes the route. A value that fails is rejected with `422` and the fixed message `settings.github_url_invalid`.
- Validation, web URL: a custom value must be `https`, have a host only, and contain no userinfo, no port, no path, no query, and no fragment. A value that fails is rejected with `422` and the fixed message `settings.github_url_invalid`.
- Token scope: the GitHub token is sent only to the configured API base URL. It is never sent to any other host, and never on a redirect (redirects are not followed).
- Interaction with the SSRF rules: the configured host is trusted, because the admin entered it. The HTTPS rule applies to it. The resolved-address check and its opt-out are not applied to the GitHub host, and no other host is contacted for GitHub. Source: the same as the registry rules above, for the scope and redirect rules; this is a Decided (2026-11-06, user, #184) exception for the admin-set host.

## GitHub token scope

- Fine-grained personal access token only in v1. No GitHub App support.
- Required permissions:
  - Metadata: read (always included in fine-grained tokens)
  - Code scanning alerts: read and write
  - Issues: read and write, for automatic and manual issue creation (`POST /api/v1/cves/:id/issue` is always available, so a token without it can still sync SARIF but cannot create issues)
- Verified (2026-11-03) against GitHub's "Permissions required for fine-grained personal access tokens": `POST /repos/{owner}/{repo}/code-scanning/sarifs` needs Code scanning alerts write; `GET .../code-scanning/sarifs/{sarif_id}` and `GET .../code-scanning/alerts` need Code scanning alerts read; `POST` and `GET /repos/{owner}/{repo}/issues` need Issues write and read; `GET /repos/{owner}/{repo}` needs Metadata read. Decided (2026-11-03, delegated): Contents: read is dropped, because no endpoint dockward calls needs it.
- The Health page reports missing scopes. See [frontend.md](frontend.md).
- Decided (2026-11-03, delegated): the Health check tests granted permissions by calling endpoints, not by reading headers. `X-Accepted-GitHub-Permissions` reports what an endpoint needs, not what the token has. The probes are `GET /repos/{owner}/{repo}` (Metadata read), `GET /repos/{owner}/{repo}/code-scanning/alerts?per_page=1` (Code scanning alerts read), and `GET /repos/{owner}/{repo}/issues?per_page=1` (Issues read). A `401` marks the token invalid and a `403` marks that permission missing. Write permissions cannot be probed without writing, so a missing write permission shows up as a failed upload or issue call in Sync jobs. See [api.md](api.md).
- Decided (2026-11-03, user, #21): the credential test always runs the issues probe. A `403` there is a warning, not a failure: the check is reported with `ok: true` and `warning: "issues_permission_missing"`, and the detail says the Issues permission is needed for automatic and manual issues. The test still passes, because SARIF upload does not need Issues. Saving a mapping with `auto_create_issues` on runs the same probe on the mapping's repository and rejects a `403` with `422 validation_failed` ("the GitHub token lacks the Issues permission needed for auto-created issues").
- Decided (2026-11-03, delegated): classifying probe responses. GitHub returns `403` both for a missing permission and for a repository where code scanning is unavailable. Neither case has a machine-readable code, so dockward matches the error `message`, ignoring case:
  - `403` with "Resource not accessible by personal access token": the permission is missing (GitHub docs, Troubleshooting the REST API, "Resource not accessible"). The `X-Accepted-GitHub-Permissions` response header names the permission the endpoint needs, and it is copied into `detail`.
  - Code scanning probe, `403` whose message contains "code scanning is not enabled", "advanced security must be enabled", or "code security must be enabled": code scanning is unavailable for the repository. This is reported as `code_scanning: "unavailable"`, not as a missing permission.
  - Code scanning probe, `404` with "no analysis found": the token can read alerts, but no analysis has been uploaded yet. This is healthy, `code_scanning: "no_analysis_yet"`.
  - Any other `404`: the token cannot see the repository, because it is not among the token's selected repositories or the owner or name is wrong.
  - Any other `403`: reported as a missing permission, with the raw message in `detail`.
  - Sources: the GitHub REST OpenAPI description (`code_scanning_forbidden_read`: "Response if GitHub Advanced Security is not enabled for this repository"; `404` "Resource not found"). The message texts match what GitHub's own `github/gh-gei` (`no analysis found`, analyses endpoint) and two independent clients (`flanksource/config-db`, `ArloL/drifty`) check for. GitHub can reword a message. An unmatched message falls back to the generic `403` or `404` rule, which surfaces an error and never hides one. The live smoke test records the real response bodies.
- Decided (2026-11-06, user, #178): the GitHub credential test lists the repository first (`GET /user/repos`, first repository returned, see [api.md](api.md), "Test button"), then runs the same three probes on it. The token is never logged or returned. The result names only the repository, never the token. A `401` or `403` on the list call is classified by the same rules as the probes above. The mapping-save probe is unchanged and still uses the mapping's explicit repository.
- Verified (2026-11-03): code scanning, and with it SARIF upload, is available only for public repositories on github.com and for organization-owned repositories on GitHub Team or Enterprise with GitHub Code Security enabled (GitHub docs, `data/reusables/gated-features/code-scanning.md`). A private repository owned by a personal account cannot receive uploads. Decided (2026-11-03, delegated): saving a mapping runs the code scanning probe and rejects `unavailable` with `422 code_scanning_unavailable`, so the problem shows when the mapping is set up, not at the first sync.

## OPEN

- Decided (2026-11-03): local passwords have a minimum of 15 characters (OWASP Authentication Cheat Sheet, accounts without MFA). Argon2id parameters are unchanged (19456 KiB, 2 iterations, parallelism 1).
- Decided (2026-11-03): backup runs from the admin UI (Settings > Backup and restore). Restore runs from the CLI only, with the app stopped. See "Backup and restore".
- Decided (2026-11-03): CSRF uses the signed double-submit variant. See "Hardening".
- Decided (2026-11-03): `DOCKWARD_ALLOW_PRIVATE_REGISTRIES` is environment-only. See "Outbound HTTP (SSRF)".
- Decided (2026-11-03): key re-encrypt is a CLI command only, run offline with the app stopped and both keys in the environment. It is not an HTTP route and not in the admin UI. It runs in one transaction and appends a `key.rotate` audit row (actor `cli`) after the rewrite. See "Key rotation".
- Decided (2026-11-03): the OIDC, user management, alert settings, and backup/restore screens live in a fifth Admin tab, "Settings", after Health. See [frontend.md](frontend.md) for the tabs.
- Decided (2026-11-03): user creation and first-run. Local accounts are created by an admin in Settings > Users, which also handles delete and role change. OIDC accounts are created on first successful login. The first local account on a fresh install is Admin, and the setup route closes permanently once any user exists. The setup page design needs user approval before build.

## CONFLICT

- CONFLICT: the webhook exemption in `backend/src/auth/csrf.rs` (`/api/v1/webhooks/` is exempt from CSRF) and its test still exist at `origin/main`. The webhook route is removed, so the exemption is dead. Unresolved until the code is removed.
- CONFLICT: the HKDF labels and cookie names. Decision 54 renames them to `dockward/*` and `__Host-dockward_*`, and the code uses those names. The stored-data migration of decision 56 was removed (PR #307), so there is no re-encryption step to describe. Decision 54 also says the existing sessions are reset; no reset is required on a fresh install.
- CONFLICT: the redirect and `Authorization` rules for registries are specified in spinoff section 3. The current code has no registry client on `origin/main`, so they are not verified against code.
