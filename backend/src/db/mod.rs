use std::path::{Path, PathBuf};

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};

pub mod acceptances;
pub mod advisory_lookups;
pub mod alert_channels;
pub mod alert_deliveries;
#[cfg(test)]
mod alias_migration;
#[allow(dead_code)] // Used by the audit writer and the admin audit list.
pub mod audit;
pub mod backup;
#[allow(dead_code)] // Used by the login service and the OIDC settings in #18.
pub mod config;
pub mod credentials;
pub mod dashboard;
pub mod db_refresh;
pub mod discovery;
pub mod findings;
pub mod github_issues;
#[allow(dead_code)] // Used by the GitHub re-key (#311, slices 5 and 6b).
pub mod github_rekeys;
pub mod hubs;
pub mod image_sources;
pub mod job_log;
pub mod job_runs;
#[allow(dead_code)] // Used by the job worker and the retry route.
pub mod jobs;
pub mod key_rotation;
pub mod publish;
pub mod retention;
pub mod scan_runs;
pub mod scanner_releases;
pub mod scans;
#[allow(dead_code)] // Used by the setup and login services.
pub mod setup;
pub mod sources;
#[allow(dead_code)] // Used by the pull and eviction jobs (Steps 4 and 5).
pub mod storage;
pub mod sync_reports;
pub mod totp;
#[allow(dead_code)] // Used by the session service and the account and admin routes.
pub mod users;

use crate::error::AppError;

/// File name of the SQLite database inside `DOCKWARD_DATA_DIR`.
pub const DB_FILE_NAME: &str = "dockward.db";

/// Table that marks a Dockward `main` database. Its presence refuses the file (decision 21).
pub const LEGACY_TABLE: &str = "repo_mappings";

/// The fixed refusal text for a legacy database (specs/spinoff-local-scan.md, section 9).
pub const LEGACY_DATABASE_ERROR: &str =
    "this database was created by HarborGate and cannot be used by this version";

/// Connection options for the database at `path`. Foreign keys are enforced on
/// every connection, and WAL is set. Both are set explicitly so a change in the
/// library default cannot switch enforcement off.
pub fn connect_options(path: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
}

/// Full path of the database file for a data directory.
pub fn database_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DB_FILE_NAME)
}

/// Opens the pool for the database in `data_dir`. A legacy database is refused before any
/// migration runs. Then the embedded schema is applied.
pub async fn open(data_dir: &Path) -> Result<SqlitePool, AppError> {
    let pool = SqlitePoolOptions::new()
        .connect_with(connect_options(&database_path(data_dir)))
        .await
        .map_err(|_| AppError::InternalError)?;
    refuse_legacy(&pool).await?;
    migrate(&pool).await?;
    Ok(pool)
}

/// Refuses a database that holds the `repo_mappings` table. The check runs before the
/// migrator, because a legacy file would otherwise be left at its old schema.
pub async fn refuse_legacy(pool: &SqlitePool) -> Result<(), AppError> {
    let found: Option<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1")
            .bind(LEGACY_TABLE)
            .fetch_optional(pool)
            .await
            .map_err(|_| AppError::InternalError)?;
    if found.is_some() {
        return Err(AppError::LegacyDatabase);
    }
    Ok(())
}

/// Applies the embedded migrations in `backend/migrations/`.
pub async fn migrate(pool: &SqlitePool) -> Result<(), AppError> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|_| AppError::InternalError)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A single-connection in-memory pool with the same foreign key setting.
    pub(crate) async fn test_pool() -> Result<SqlitePool, AppError> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| AppError::InternalError)?;
        migrate(&pool).await?;
        Ok(pool)
    }

    /// Names of every table in the database, sorted. Test helper.
    async fn table_names(pool: &SqlitePool) -> Result<Vec<String>, AppError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> '_sqlx_migrations'
             ORDER BY name",
        )
        .fetch_all(pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        Ok(rows.into_iter().map(|(name,)| name).collect())
    }

    /// One user, a GitHub credential, and one source that uses it. Test values only.
    async fn seed_source(pool: &SqlitePool) -> Result<(), AppError> {
        sqlx::query!(
            "INSERT INTO users (id, username, role, auth_provider)
             VALUES ('user-1', 'test-user', 'user', 'local')"
        )
        .execute(pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        sqlx::query!(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('cred-gh', 'user-1', 'github', 'v1:test')"
        )
        .execute(pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        sqlx::query!(
            "INSERT INTO image_sources (
                id, user_id, hub_id, repository, tag_value, github_cred_id, github_owner, github_repo)
             VALUES ('src-1', 'user-1', 'hub-default-ghcr', 'nrosier/walley', 'latest',
                'cred-gh', 'owner', 'repo')"
        )
        .execute(pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        Ok(())
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced_on_the_pool() -> Result<(), AppError> {
        let pool = test_pool().await?;
        let row = sqlx::query!("PRAGMA foreign_keys")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(row.foreign_keys, Some(1));
        Ok(())
    }

    #[tokio::test]
    async fn orphan_insert_is_rejected() -> Result<(), AppError> {
        let pool = test_pool().await?;
        let result = sqlx::query!(
            "INSERT INTO user_credentials (id, user_id, label, encrypted_token)
             VALUES ('cred-x', 'no-such-user', 'label', 'v1:test')"
        )
        .execute(&pool)
        .await;
        assert!(result.is_err(), "orphan credential was accepted");
        Ok(())
    }

    #[tokio::test]
    async fn restrict_blocks_deleting_a_credential_in_use() -> Result<(), AppError> {
        let pool = test_pool().await?;
        seed_source(&pool).await?;

        let deleted = sqlx::query!("DELETE FROM user_credentials WHERE id = 'cred-gh'")
            .execute(&pool)
            .await;
        assert!(deleted.is_err(), "RESTRICT did not block the delete");

        let remaining = sqlx::query!("SELECT COUNT(*) AS n FROM user_credentials")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(remaining.n, 1);
        Ok(())
    }

    /// The fresh migration creates exactly the spinoff tables of section 9 and none of the
    /// removed Harbor tables.
    #[tokio::test]
    async fn migration_creates_exactly_the_spinoff_tables() -> Result<(), AppError> {
        let pool = test_pool().await?;
        let tables = table_names(&pool).await?;
        let expected = [
            "advisory_lookups",
            "alert_carryovers",
            "alert_channels",
            "alert_deliveries",
            "analysis_retirements",
            "audit_log",
            "carryover_refs",
            "cve_acceptances",
            "cve_findings",
            "github_issues",
            "hubs",
            "image_platforms",
            "image_sources",
            "images",
            "issue_rekeys",
            "job_log_lines",
            "job_log_steps",
            "job_runs",
            "jobs",
            "publish_reports",
            "scan_runs",
            "scanner_databases",
            "scanner_findings",
            "scanner_releases",
            "source_credentials",
            "system_config",
            "tag_observations",
            "totp_recovery_codes",
            "totp_secrets",
            "user_credentials",
            "users",
            "vulnerability_aliases",
        ];
        assert_eq!(tables, expected);
        Ok(())
    }

    /// Section 2: a default install has ghcr.io and docker.io, both of kind default.
    #[tokio::test]
    async fn default_hubs_are_seeded() -> Result<(), AppError> {
        let pool = test_pool().await?;
        let rows: Vec<(String, String, Option<String>)> =
            sqlx::query_as("SELECT host, kind, pull_endpoint FROM hubs ORDER BY host")
                .fetch_all(&pool)
                .await
                .map_err(|_| AppError::InternalError)?;
        assert_eq!(
            rows,
            vec![
                ("docker.io".to_owned(), "default".to_owned(), None),
                ("ghcr.io".to_owned(), "default".to_owned(), None),
            ]
        );
        Ok(())
    }

    /// Section 9: a database that holds `repo_mappings` is refused before the migrator runs,
    /// and no migration is applied to it.
    #[tokio::test]
    async fn legacy_repo_mappings_database_is_refused_before_migration() -> Result<(), AppError> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| AppError::InternalError)?;
        sqlx::query("CREATE TABLE repo_mappings (id TEXT PRIMARY KEY)")
            .execute(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        let refused = refuse_legacy(&pool).await;
        assert!(matches!(refused, Err(AppError::LegacyDatabase)));
        let names = table_names(&pool).await?;
        assert_eq!(names, vec!["repo_mappings".to_owned()], "no migration ran");
        assert_eq!(
            LEGACY_DATABASE_ERROR,
            "this database was created by HarborGate and cannot be used by this version"
        );
        Ok(())
    }

    /// `open` refuses a file that holds `repo_mappings` at pool open, before the spinoff
    /// schema is created in it.
    #[tokio::test]
    async fn open_refuses_a_legacy_file_and_creates_no_tables() -> Result<(), AppError> {
        let dir = std::env::temp_dir().join(format!("dockward-legacy-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|_| AppError::InternalError)?;
        let legacy = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(connect_options(&database_path(&dir)))
            .await
            .map_err(|_| AppError::InternalError)?;
        sqlx::query("CREATE TABLE repo_mappings (id TEXT PRIMARY KEY)")
            .execute(&legacy)
            .await
            .map_err(|_| AppError::InternalError)?;
        legacy.close().await;

        let opened = open(&dir).await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(opened, Err(AppError::LegacyDatabase)));
        Ok(())
    }

    #[tokio::test]
    async fn file_database_uses_wal() -> Result<(), AppError> {
        let dir = std::env::temp_dir().join(format!("dockward-db-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|_| AppError::InternalError)?;
        let pool = open(&dir).await?;
        // PRAGMA results have no column type the macro can infer, so this read is
        // the one runtime query in the module.
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(mode, "wal");
        Ok(())
    }

    /// Seeds one image, one platform and one scan run with `trigger`, plus a tag observation.
    async fn seed_run(pool: &SqlitePool, trigger: &str) -> Result<(), sqlx::Error> {
        for sql in [
            "INSERT INTO images (id, hub_id, repository, digest, is_index)
             VALUES ('i1', 'hub-default-ghcr', 'o/app', 'sha256:aa', 0)",
            "INSERT INTO image_platforms (id, image_id, platform, platform_digest, state)
             VALUES ('p1', 'i1', 'linux/amd64', 'sha256:a1', 'stored')",
            "INSERT INTO tag_observations (source_id, tag, image_id) VALUES ('src-1', 'v1', 'i1')",
        ] {
            sqlx::query(sql).execute(pool).await?;
        }
        sqlx::query(
            "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status, finished_at)
             VALUES ('r1', 'p1', 'grype', ?, 'done', 5)",
        )
        .bind(trigger)
        .execute(pool)
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn manual_trigger_run_inserts_and_fk_check_clean() -> Result<(), AppError> {
        let pool = test_pool().await?;
        seed_source(&pool).await?;
        seed_run(&pool, "manual")
            .await
            .map_err(|_| AppError::InternalError)?;
        sqlx::query(
            "INSERT INTO scanner_findings (run_id, cve_id, severity) VALUES ('r1', 'CVE-1', 'HIGH')",
        )
        .execute(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        let violations: Vec<(String,)> =
            sqlx::query_as(r#"SELECT "table" FROM pragma_foreign_key_check"#)
                .fetch_all(&pool)
                .await
                .map_err(|_| AppError::InternalError)?;
        assert!(violations.is_empty());
        let tags: Vec<(String,)> = sqlx::query_as("SELECT image_tag FROM newest_digest_tags")
            .fetch_all(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(tags, vec![("v1".to_owned(),)]);
        let seen: Vec<(String,)> = sqlx::query_as("SELECT image_tag FROM tag_scan_times")
            .fetch_all(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(seen, vec![("v1".to_owned(),)]);
        // A trigger outside the list is still refused.
        let bad = sqlx::query(
            "INSERT INTO scan_runs (id, image_platform_id, scanner, trigger, status)
             VALUES ('r2', 'p1', 'grype', 'bogus', 'queued')",
        )
        .execute(&pool)
        .await;
        assert!(bad.is_err());
        Ok(())
    }

    /// Migration 0008 rebuilds `scan_runs`: runs and their findings written before it survive,
    /// the index and both views are back, and the foreign keys are still enforced afterwards.
    #[tokio::test]
    async fn migration_0008_keeps_runs_findings_index_and_views() -> Result<(), AppError> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| AppError::InternalError)?;
        let migrator = sqlx::migrate!("./migrations");
        migrator
            .run_to(6, &pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        seed_source(&pool).await?;
        seed_run(&pool, "first_pull")
            .await
            .map_err(|_| AppError::InternalError)?;
        sqlx::query(
            "INSERT INTO scanner_findings (run_id, cve_id, severity) VALUES ('r1', 'CVE-1', 'HIGH')",
        )
        .execute(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        migrator
            .run(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        let runs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_runs")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        let findings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scanner_findings")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!((runs, findings), (1, 1));
        // Every migration applied, in order: 0007 (aliases), 0008 (manual trigger), 0009 (TOTP), 0010 (empty jobs), 0012 (CVE scanners), 0013 (id reason), 0014 (fixed note), 0015 (acceptance kind), 0016 (advisory lookups), 0017 (scanner releases).
        let versions: Vec<i64> =
            sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
                .fetch_all(&pool)
                .await
                .map_err(|_| AppError::InternalError)?;
        assert_eq!(versions, (1..=17).collect::<Vec<i64>>());
        let names: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master
             WHERE name IN ('idx_scan_runs_current', 'newest_digest_tags', 'tag_scan_times',
                            'scan_runs_new')
             ORDER BY name",
        )
        .fetch_all(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        let names: Vec<String> = names.into_iter().map(|(name,)| name).collect();
        assert_eq!(
            names,
            [
                "idx_scan_runs_current",
                "newest_digest_tags",
                "tag_scan_times"
            ]
        );
        let enforced: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(enforced, 1);
        // Deleting the platform still cascades through the rebuilt table to the findings.
        sqlx::query("DELETE FROM image_platforms WHERE id = 'p1'")
            .execute(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scanner_findings")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(left, 0);
        Ok(())
    }
    /// Migration 0015 adds `cve_acceptances.kind`: a row written before it reads as
    /// `accepted`, only `accepted` and `false_positive` are allowed, and the partial unique
    /// index still allows one active verdict per source and CVE, of either kind.
    #[tokio::test]
    async fn migration_0015_keeps_existing_acceptances_as_accepted() -> Result<(), AppError> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| AppError::InternalError)?;
        let migrator = sqlx::migrate!("./migrations");
        migrator
            .run_to(14, &pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        seed_source(&pool).await?;
        sqlx::query(
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by, created_by_username)
             VALUES ('old', 'src-1', 'CVE-1', 'before 0015', 'user-1', 'test-user')",
        )
        .execute(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        migrator
            .run(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        let kind: String = sqlx::query_scalar("SELECT kind FROM cve_acceptances WHERE id = 'old'")
            .fetch_one(&pool)
            .await
            .map_err(|_| AppError::InternalError)?;
        assert_eq!(kind, "accepted");
        // Any other kind is refused by the CHECK.
        let bad = sqlx::query(
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by_username, kind)
             VALUES ('bad', 'src-1', 'CVE-2', '', 'test-user', 'ignored')",
        )
        .execute(&pool)
        .await;
        assert!(bad.is_err());
        // A false positive for the same CVE is refused while the old acceptance is active.
        let second = sqlx::query(
            "INSERT INTO cve_acceptances (id, source_id, cve_id, reason, created_by_username, kind)
             VALUES ('fp', 'src-1', 'CVE-1', '', 'test-user', 'false_positive')",
        )
        .execute(&pool)
        .await;
        assert!(second.is_err());
        let index: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'idx_cve_acceptances_active'",
        )
        .fetch_one(&pool)
        .await
        .map_err(|_| AppError::InternalError)?;
        assert_eq!(index, 1);
        Ok(())
    }
}
