//! SQLite persistence layer for traffic history and bandwidth rules.
//!
//! Uses `rusqlite` with bundled SQLite. Handles:
//! - Per-process traffic history (5-second granularity)
//! - Bandwidth rule profiles
//! - Auto-pruning of data older than 90 days

mod history;
mod rules;

use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use rusqlite::Connection;
use serde::Serialize;
use ts_rs::TS;

/// Manages the SQLite database for traffic history.
pub struct Database {
    pub(super) conn: Mutex<Connection>,
}

/// A single traffic history record.
#[derive(Debug, Clone, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings.ts")]
pub struct TrafficRecord {
    #[ts(type = "number")]
    pub timestamp: i64,
    pub pid: u32,
    pub process_name: String,
    pub exe_path: String,
    #[ts(type = "number")]
    pub bytes_sent: u64,
    #[ts(type = "number")]
    pub bytes_recv: u64,
    pub upload_speed: f64,
    pub download_speed: f64,
}

/// Summary of a process's total traffic over a time window.
#[derive(Debug, Clone, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings.ts")]
pub struct TrafficSummary {
    pub process_name: String,
    pub exe_path: String,
    #[ts(type = "number")]
    pub total_sent: u64,
    #[ts(type = "number")]
    pub total_recv: u64,
    #[ts(type = "number")]
    pub total_bytes: u64,
}

/// A saved bandwidth rule from the database.
#[derive(Debug, Clone, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings.ts")]
pub struct SavedRule {
    pub exe_path: String,
    pub process_name: String,
    #[ts(type = "number")]
    pub download_bps: u64,
    #[ts(type = "number")]
    pub upload_bps: u64,
    pub blocked: bool,
}

impl Database {
    /// Open or create the database at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS traffic_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                exe_path TEXT NOT NULL DEFAULT '',
                bytes_sent INTEGER NOT NULL DEFAULT 0,
                bytes_recv INTEGER NOT NULL DEFAULT 0,
                upload_speed REAL NOT NULL DEFAULT 0.0,
                download_speed REAL NOT NULL DEFAULT 0.0
            );
            CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_traffic_process ON traffic_history(process_name);

            CREATE TABLE IF NOT EXISTS bandwidth_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_name TEXT NOT NULL DEFAULT 'default',
                exe_path TEXT NOT NULL,
                process_name TEXT NOT NULL DEFAULT '',
                download_bps INTEGER NOT NULL DEFAULT 0,
                upload_bps INTEGER NOT NULL DEFAULT 0,
                blocked INTEGER NOT NULL DEFAULT 0,
                UNIQUE(profile_name, exe_path)
            );
            ",
        )?;

        // Enable WAL mode for better concurrent read performance.
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

/// Current Unix timestamp in seconds.
pub fn chrono_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Helper: open an in-memory database for testing.
    pub(super) fn open_memory_db() -> Database {
        Database::open(Path::new(":memory:")).expect("Failed to open in-memory database")
    }

    /// Helper: create a TrafficRecord with the given fields.
    pub(super) fn make_record(
        timestamp: i64,
        pid: u32,
        process_name: &str,
        exe_path: &str,
        bytes_sent: u64,
        bytes_recv: u64,
    ) -> TrafficRecord {
        TrafficRecord {
            timestamp,
            pid,
            process_name: process_name.to_string(),
            exe_path: exe_path.to_string(),
            bytes_sent,
            bytes_recv,
            upload_speed: bytes_sent as f64,
            download_speed: bytes_recv as f64,
        }
    }

    #[test]
    fn test_open_creates_tables() {
        let db = open_memory_db();
        // Verify we can query both tables without error (they exist).
        let history = db.query_history(0, i64::MAX, None);
        assert!(history.is_ok());
        let rules = db.load_rules("default");
        assert!(rules.is_ok());
    }
}
