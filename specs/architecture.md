# Architecture

Purpose: system overview, components, data flow, and deployment shape for dockward 0.2.0.

Status: this file describes the built architecture of 0.2.0 on `main`. The spinoff that produced it is specified in [spinoff-local-scan.md](spinoff-local-scan.md), with its binding decisions in [spinoff-decisions.md](spinoff-decisions.md). Harbor is removed entirely: there is no Harbor client, webhook receiver, poller, Harbor API call, project webhook, or Harbor credential type.

## Overview

- Dockward is a local-first, multi-tenant security relay.
- It discovers images in OCI registries ("hubs"), pulls each platform image into a local OCI layout on disk through its own registry client, scans it with pinned Trivy and Grype executables that run out of process, converts the results to SARIF 2.1.0, and publishes them to GitHub Code Scanning and GitHub issues.
- No Docker daemon or socket is used.
- Default hubs are `ghcr.io` and `docker.io`. Admins can add and remove custom hubs (decisions 7, 13).

## Components

- **Axum API** (`backend/src/api/`): setup, local and OIDC login, sessions, sources, hubs, credentials, images, jobs, CVEs, dashboard, and admin routes. The route list is in [api.md](api.md).
- **Registry client** (`backend/src/services/registry/`): an OCI Distribution client on `reqwest`. It checks the address of every hop (spinoff sections 3 and 12).
- **Discovery** (`backend/src/services/discovery/`): lists tags, matches each source's tag value, and records tag observations.
- **Image store** (`backend/src/services/storage/`, `backend/src/db/storage.rs`): OCI layouts under `<data dir>/images`, count-based retention, and eviction.
- **Scanner runner** (`backend/src/services/scan/`, `backend/src/services/scanner/`): runs the pinned Trivy and Grype executables by absolute path, with a clean environment, one process at a time.
- **Publish** (`backend/src/services/publish/`): builds the merged SARIF, uploads it to Code Scanning, and runs the issue rules.
- **Durable job queue**: the `jobs` table, drained by one in-process worker (`backend/src/worker/`).
- **SQLite database**: `<data dir>/dockward.db` in the `/data` volume, WAL mode, foreign keys on.
- **Frontend SPA** (React, Vite, TypeScript), embedded in the binary.

## Data flow

Spinoff sections 5, 6 and 8 hold the rules.

1. **Discover** (hourly per repository): list the repository's tags, match each source's tag value (an exact tag, or a pattern with `*` and `?`), resolve each match to its manifest digest, and record the observation. A digest that is new to the store, or a tag that now points at a different digest, queues a pull.
2. **Resolve**: fetch the manifest. An index yields one entry per platform. Attestation entries are skipped. A single manifest takes its platform from the image config.
3. **Pull** (one platform): check the free-disk guard and the size cap, download the blobs into `<data dir>/images/.tmp/<id>` with digest checks, rename the directory into place, mark the image `stored`, and run eviction.
4. **Scan**: one scan job per platform image and enabled scanner. Trivy and Grype read the local layout offline and write JSON to a file. The JSON is parsed into `scanner_findings`.
5. **Merge**: the merged `cve_findings` of each tag are recomputed in one transaction.
6. **Publish**: when every scan of the source's newest image has ended, one publish job builds one merged SARIF, uploads it to Code Scanning, and runs the issue rules.
7. **Database refresh** (daily): `db_update` jobs refresh the Trivy and Grype databases. A newer database rescans every stored platform image by digest, and then publishes each source's newest image.
8. **Alerts**: a job that fails after its last attempt raises the job-failed alert. A new CRITICAL CVE raises the CVE alert ([alerts.md](alerts.md)).

## Decisions

- Single instance only: one process and one SQLite file in the data volume. The issue-create lock is process-wide (`backend/src/services/issue_lifecycle.rs`). Carried over from HarborGate; still holds.
- Frontend and API are served from the same origin on port 8080.
- The frontend is embedded in the Rust binary. In production it is not copied to disk for runtime serving.
- No `/metrics` endpoint.
- Scanners are not linked into the app. The pinned Trivy and Grype executables are copied into the image at `/usr/local/bin/`, and the app calls them by absolute path. The app image stays `FROM scratch` (spinoff decisions 5, 23). The bundled executables are the default. A newer downloaded version under `<data dir>/scanners` overrides one, and an equal or older one is purged at startup (Decided 2026-11-14, user, #390; [integrations.md](integrations.md), "Scanner selection and the data volume").
- Environment variables are `DOCKWARD_*`. The deprecated `HARBORGATE_*` name is read as a fallback in release 0.2 only. Each fallback read logs a deprecation warning, and `DOCKWARD_*` wins when both are set. The fallback is removed in the release after 0.2 (decision 57, `backend/src/config.rs`).
- Fresh install only. There is no import from, and no upgrade of, a HarborGate database. A database that contains the `repo_mappings` table is refused at open with a fixed error (decisions 21 and 56; `backend/src/db/mod.rs`). The migration code that read HarborGate data was removed (PR #307).
- v1 includes every page listed in [frontend.md](frontend.md). Pages not yet in the router are marked there.

## Tech stack

- Backend: Rust 1.99.1, Tokio, Axum, SQLx (SQLite WAL), reqwest, OpenIDConnect-rs, Argon2, AES-GCM, zeroize.
- Scanners: Trivy 0.76.2 and Grype 0.121.3, both pinned by image digest in the Dockerfile, with the release recorded in a comment above each pin and checked by `scripts/check-scanner-pins.sh` (see [integrations.md](integrations.md), "Pinned binaries").
- Frontend: React 19, TypeScript, Vite, Tailwind CSS v4, Radix UI Primitives, Lucide React, TanStack Query v5, Recharts.
- Build: multi-stage Dockerfile (Node, Rust, the pinned scanner images, then `scratch`). See [deployment.md](deployment.md).
