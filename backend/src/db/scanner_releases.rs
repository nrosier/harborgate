//! The daily upstream check of the scanners (#390, migration 0017): one row per scanner with the
//! latest stable release GitHub named, whether it is newer than the bundled scanner, and when it
//! was checked. A failed check writes nothing.

use sqlx::SqlitePool;

use crate::error::AppError;

fn db_err<E>(_: E) -> AppError {
    AppError::InternalError
}

/// One stored check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseRow {
    pub scanner: String,
    pub latest_version: String,
    pub newer_than_bundled: bool,
    pub checked_at: i64,
}

/// Stores the answer of a check for `scanner`, replacing the previous one.
pub async fn put(
    pool: &SqlitePool,
    scanner: &str,
    latest_version: &str,
    newer_than_bundled: bool,
    checked_at: i64,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO scanner_releases (scanner, latest_version, newer_than_bundled, checked_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT (scanner) DO UPDATE SET
             latest_version = excluded.latest_version,
             newer_than_bundled = excluded.newer_than_bundled,
             checked_at = excluded.checked_at",
        scanner,
        latest_version,
        newer_than_bundled,
        checked_at
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(db_err)
}

/// The stored check of `scanner`, or `None` when no check has succeeded yet.
pub async fn get(pool: &SqlitePool, scanner: &str) -> Result<Option<ReleaseRow>, AppError> {
    let row = sqlx::query!(
        r#"SELECT scanner AS "scanner!", latest_version, newer_than_bundled AS "newer_than_bundled: bool",
                  checked_at
           FROM scanner_releases WHERE scanner = ?"#,
        scanner
    )
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    Ok(row.map(|row| ReleaseRow {
        scanner: row.scanner,
        latest_version: row.latest_version,
        newer_than_bundled: row.newer_than_bundled,
        checked_at: row.checked_at,
    }))
}
