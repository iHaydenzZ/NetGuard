//! SQLite persistence layer for traffic history and bandwidth rules.
//!
//! Uses `rusqlite` with bundled SQLite. Handles:
//! - Per-process traffic history (5-second granularity)
//! - Bandwidth rule profiles
//! - Auto-pruning of data older than 90 days

use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use rusqlite::{params, Connection};
use serde::Serialize;

/// Manages the SQLite database for traffic history.
pub struct Database {
    conn: Mutex<Connection>,
}

/// A single traffic history record.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficRecord {
    pub timestamp: i64,
    pub pid: u32,
    pub process_name: String,
    pub exe_path: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub upload_speed: f64,
    pub download_speed: f64,
}

/// Summary of a process's total traffic over a time window.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficSummary {
    pub process_name: String,
    pub exe_path: String,
    pub total_sent: u64,
    pub total_recv: u64,
    pub total_bytes: u64,
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

    /// Insert a batch of traffic snapshots (called every 5 seconds).
    pub fn insert_traffic_batch(&self, records: &[TrafficRecord]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "INSERT INTO traffic_history (timestamp, pid, process_name, exe_path, bytes_sent, bytes_recv, upload_speed, download_speed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;

        for r in records {
            stmt.execute(params![
                r.timestamp,
                r.pid,
                r.process_name,
                r.exe_path,
                r.bytes_sent,
                r.bytes_recv,
                r.upload_speed,
                r.download_speed,
            ])?;
        }
        Ok(())
    }

    /// Query traffic history within a time range.
    pub fn query_history(
        &self,
        from_timestamp: i64,
        to_timestamp: i64,
        process_name: Option<&str>,
    ) -> Result<Vec<TrafficRecord>> {
        let conn = self.conn.lock().unwrap();

        let (sql, do_filter) = if process_name.is_some() {
            (
                "SELECT timestamp, pid, process_name, exe_path, bytes_sent, bytes_recv, upload_speed, download_speed
                 FROM traffic_history
                 WHERE timestamp >= ?1 AND timestamp <= ?2 AND process_name = ?3
                 ORDER BY timestamp ASC",
                true,
            )
        } else {
            (
                "SELECT timestamp, pid, process_name, exe_path, bytes_sent, bytes_recv, upload_speed, download_speed
                 FROM traffic_history
                 WHERE timestamp >= ?1 AND timestamp <= ?2
                 ORDER BY timestamp ASC",
                false,
            )
        };

        let mut stmt = conn.prepare_cached(sql)?;

        let rows = if do_filter {
            stmt.query_map(
                params![from_timestamp, to_timestamp, process_name.unwrap()],
                map_traffic_row,
            )?
        } else {
            stmt.query_map(params![from_timestamp, to_timestamp], map_traffic_row)?
        };

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Get top consumers by total bytes over a time window.
    pub fn top_consumers(
        &self,
        from_timestamp: i64,
        to_timestamp: i64,
        limit: usize,
    ) -> Result<Vec<TrafficSummary>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT process_name, exe_path,
                    SUM(bytes_sent) as total_sent,
                    SUM(bytes_recv) as total_recv,
                    SUM(bytes_sent) + SUM(bytes_recv) as total_bytes
             FROM traffic_history
             WHERE timestamp >= ?1 AND timestamp <= ?2
             GROUP BY process_name
             ORDER BY total_bytes DESC
             LIMIT ?3",
        )?;

        let rows = stmt.query_map(params![from_timestamp, to_timestamp, limit], |row| {
            Ok(TrafficSummary {
                process_name: row.get(0)?,
                exe_path: row.get(1)?,
                total_sent: row.get(2)?,
                total_recv: row.get(3)?,
                total_bytes: row.get(4)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Prune records older than the specified number of days.
    pub fn prune_old_records(&self, max_age_days: u64) -> Result<usize> {
        let cutoff = chrono_timestamp() - (max_age_days * 86400) as i64;
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute(
            "DELETE FROM traffic_history WHERE timestamp < ?1",
            params![cutoff],
        )?;
        if deleted > 0 {
            tracing::info!("Pruned {deleted} traffic history records older than {max_age_days} days");
        }
        Ok(deleted)
    }

    /// Save a bandwidth rule to a profile.
    pub fn save_rule(
        &self,
        profile: &str,
        exe_path: &str,
        process_name: &str,
        download_bps: u64,
        upload_bps: u64,
        blocked: bool,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO bandwidth_rules (profile_name, exe_path, process_name, download_bps, upload_bps, blocked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![profile, exe_path, process_name, download_bps, upload_bps, blocked as i32],
        )?;
        Ok(())
    }

    /// Load all rules for a profile.
    pub fn load_rules(&self, profile: &str) -> Result<Vec<SavedRule>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT exe_path, process_name, download_bps, upload_bps, blocked
             FROM bandwidth_rules WHERE profile_name = ?1",
        )?;

        let rows = stmt.query_map(params![profile], |row| {
            Ok(SavedRule {
                exe_path: row.get(0)?,
                process_name: row.get(1)?,
                download_bps: row.get(2)?,
                upload_bps: row.get(3)?,
                blocked: row.get::<_, i32>(4)? != 0,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// List all profile names.
    pub fn list_profiles(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT DISTINCT profile_name FROM bandwidth_rules ORDER BY profile_name",
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Delete a rule from a profile.
    pub fn delete_rule(&self, profile: &str, exe_path: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM bandwidth_rules WHERE profile_name = ?1 AND exe_path = ?2",
            params![profile, exe_path],
        )?;
        Ok(())
    }

    /// Delete an entire profile and all its rules.
    pub fn delete_profile(&self, profile: &str) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute(
            "DELETE FROM bandwidth_rules WHERE profile_name = ?1",
            params![profile],
        )?;
        Ok(deleted)
    }
}

/// A saved bandwidth rule from the database.
#[derive(Debug, Clone, Serialize)]
pub struct SavedRule {
    pub exe_path: String,
    pub process_name: String,
    pub download_bps: u64,
    pub upload_bps: u64,
    pub blocked: bool,
}

fn map_traffic_row(row: &rusqlite::Row) -> rusqlite::Result<TrafficRecord> {
    Ok(TrafficRecord {
        timestamp: row.get(0)?,
        pid: row.get(1)?,
        process_name: row.get(2)?,
        exe_path: row.get(3)?,
        bytes_sent: row.get(4)?,
        bytes_recv: row.get(5)?,
        upload_speed: row.get(6)?,
        download_speed: row.get(7)?,
    })
}

/// Current Unix timestamp in seconds.
pub fn chrono_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
