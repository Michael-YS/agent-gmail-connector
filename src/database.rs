//! SQLite persistence bootstrap, migration status, and safe backups.

use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("invalid SQLite URL: {0}")]
    InvalidUrl(String),
    #[error("database is not at the latest schema; run `agentmail migrate`")]
    PendingMigrations { pending: Vec<i64> },
    #[error("backup target already exists: {0}")]
    BackupExists(PathBuf),
    #[error("backup target must not be the live database")]
    BackupIsDatabase,
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
pub struct Database {
    pool: SqlitePool,
    database_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationStatus {
    pub current_version: i64,
    pub latest_version: i64,
    pub applied: Vec<i64>,
    pub pending: Vec<i64>,
}

impl MigrationStatus {
    pub fn is_current(&self) -> bool {
        self.pending.is_empty() && self.current_version == self.latest_version
    }
}

impl Database {
    /// Open SQLite without applying migrations. `serve` should call
    /// `ensure_current` and refuse to start when this reports pending work.
    pub async fn connect(database_url: impl Into<String>) -> Result<Self, DatabaseError> {
        let database_url = database_url.into();
        let options = SqliteConnectOptions::from_str(&database_url)
            .map_err(|e| DatabaseError::InvalidUrl(e.to_string()))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(std::time::Duration::from_secs(5));
        let max_connections = if database_url.contains(":memory:") {
            1
        } else {
            5
        };
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect_with(options)
            .await?;

        Ok(Self { pool, database_url })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    pub async fn migrate(&self) -> Result<(), DatabaseError> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    pub async fn migration_status(&self) -> Result<MigrationStatus, DatabaseError> {
        let applied_rows = match sqlx::query_as::<_, (i64,)>(
            "SELECT version FROM _sqlx_migrations WHERE success = TRUE ORDER BY version",
        )
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => rows,
            Err(error) if is_missing_migrations_table(&error) => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        let applied: Vec<i64> = applied_rows.into_iter().map(|(v,)| v).collect();
        let latest_version = MIGRATOR.iter().map(|m| m.version).max().unwrap_or(0);
        let current_version = applied.last().copied().unwrap_or(0);
        let pending = MIGRATOR
            .iter()
            .map(|m| m.version)
            .filter(|v| !applied.contains(v))
            .collect();
        Ok(MigrationStatus {
            current_version,
            latest_version,
            applied,
            pending,
        })
    }

    pub async fn ensure_current(&self) -> Result<MigrationStatus, DatabaseError> {
        let status = self.migration_status().await?;
        if !status.is_current() {
            return Err(DatabaseError::PendingMigrations {
                pending: status.pending.clone(),
            });
        }
        Ok(status)
    }

    /// Create a consistent SQLite backup through SQLite's online `VACUUM INTO`
    /// mechanism. Existing files are never overwritten.
    pub async fn backup(&self, target: impl AsRef<Path>) -> Result<PathBuf, DatabaseError> {
        let target = target.as_ref();
        if target.exists() {
            return Err(DatabaseError::BackupExists(target.to_path_buf()));
        }
        if let Some(live_path) = sqlite_file_path(&self.database_url)
            && live_path
                == target
                    .canonicalize()
                    .unwrap_or_else(|_| target.to_path_buf())
        {
            return Err(DatabaseError::BackupIsDatabase);
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let escaped = target.to_string_lossy().replace('\'', "''");
        sqlx::query(&format!("VACUUM INTO '{escaped}'"))
            .execute(&self.pool)
            .await?;
        Ok(target.to_path_buf())
    }
}

fn is_missing_migrations_table(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(database_error) => database_error
            .message()
            .contains("no such table: _sqlx_migrations"),
        _ => false,
    }
}
fn sqlite_file_path(url: &str) -> Option<PathBuf> {
    let raw = url.strip_prefix("sqlite:")?.split('?').next()?;
    if raw.is_empty() || raw == ":memory:" || raw == "//:memory:" {
        return None;
    }
    let path = raw.strip_prefix("//").unwrap_or(raw);
    Some(
        PathBuf::from(path)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(path)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn migration_status_requires_explicit_migrate_and_schema_has_core_tables() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let before = database.migration_status().await.unwrap();
        assert!(!before.is_current());
        database.migrate().await.unwrap();
        let after = database.ensure_current().await.unwrap();
        assert!(after.is_current());
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('users', 'gmail_connections', 'access_keys', 'audit_events', 'instance_counters', 'authorized_gmail_subjects')")
            .fetch_one(database.pool()).await.unwrap();
        assert_eq!(count.0, 6);
    }

    #[tokio::test]
    async fn foreign_keys_are_enabled_on_all_pool_connections() {
        let dir = tempdir().unwrap();
        let database =
            Database::connect(format!("sqlite://{}", dir.path().join("fk.db").display()))
                .await
                .unwrap();
        let (a, b, c, d, e) = tokio::join!(
            sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys").fetch_one(database.pool()),
            sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys").fetch_one(database.pool()),
            sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys").fetch_one(database.pool()),
            sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys").fetch_one(database.pool()),
            sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys").fetch_one(database.pool()),
        );
        for result in [a, b, c, d, e] {
            assert_eq!(result.unwrap(), 1);
        }
    }
    #[tokio::test]
    async fn backup_is_consistent_and_non_overwriting() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("agentmail.db");
        let target = dir.path().join("backup.db");
        let database = Database::connect(format!("sqlite://{}", source.display()))
            .await
            .unwrap();
        database.migrate().await.unwrap();
        sqlx::query("UPDATE instance_counters SET counter_value = 4 WHERE counter_name = 'historical_gmail_authorizations'")
            .execute(database.pool()).await.unwrap();
        database.backup(&target).await.unwrap();
        assert!(target.is_file());
        assert!(matches!(
            database.backup(&target).await,
            Err(DatabaseError::BackupExists(_))
        ));
        let copied = Database::connect(format!("sqlite://{}", target.display()))
            .await
            .unwrap();
        let value: (i64,) = sqlx::query_as("SELECT counter_value FROM instance_counters WHERE counter_name = 'historical_gmail_authorizations'")
            .fetch_one(copied.pool()).await.unwrap();
        assert_eq!(value.0, 4);
    }
}
