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
            tracing::info!(
                "Pruned {deleted} traffic history records older than {max_age_days} days"
            );
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Helper: open an in-memory database for testing.
    fn open_memory_db() -> Database {
        Database::open(Path::new(":memory:")).expect("Failed to open in-memory database")
    }

    /// Helper: create a TrafficRecord with the given fields.
    fn make_record(
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

    #[test]
    fn test_insert_and_query_traffic() {
        let db = open_memory_db();
        let records = vec![
            make_record(1000, 1, "chrome.exe", "C:\\chrome.exe", 100, 200),
            make_record(1005, 1, "chrome.exe", "C:\\chrome.exe", 150, 250),
        ];

        db.insert_traffic_batch(&records).unwrap();
        let results = db.query_history(0, 2000, None).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].timestamp, 1000);
        assert_eq!(results[0].bytes_sent, 100);
        assert_eq!(results[0].bytes_recv, 200);
        assert_eq!(results[1].timestamp, 1005);
        assert_eq!(results[1].bytes_sent, 150);
    }

    #[test]
    fn test_query_history_with_process_filter() {
        let db = open_memory_db();
        let records = vec![
            make_record(1000, 1, "chrome.exe", "C:\\chrome.exe", 100, 200),
            make_record(1000, 2, "firefox.exe", "C:\\firefox.exe", 300, 400),
            make_record(1005, 1, "chrome.exe", "C:\\chrome.exe", 150, 250),
        ];

        db.insert_traffic_batch(&records).unwrap();

        // Filter for chrome only.
        let chrome = db.query_history(0, 2000, Some("chrome.exe")).unwrap();
        assert_eq!(chrome.len(), 2);
        for r in &chrome {
            assert_eq!(r.process_name, "chrome.exe");
        }

        // Filter for firefox only.
        let firefox = db.query_history(0, 2000, Some("firefox.exe")).unwrap();
        assert_eq!(firefox.len(), 1);
        assert_eq!(firefox[0].process_name, "firefox.exe");

        // Filter for non-existent process.
        let none = db.query_history(0, 2000, Some("notepad.exe")).unwrap();
        assert_eq!(none.len(), 0);
    }

    #[test]
    fn test_top_consumers() {
        let db = open_memory_db();
        let records = vec![
            // chrome: 100+200 sent, 200+400 recv = 900 total
            make_record(1000, 1, "chrome.exe", "C:\\chrome.exe", 100, 200),
            make_record(1005, 1, "chrome.exe", "C:\\chrome.exe", 200, 400),
            // firefox: 500 sent, 500 recv = 1000 total
            make_record(1000, 2, "firefox.exe", "C:\\firefox.exe", 500, 500),
            // notepad: 10 sent, 10 recv = 20 total
            make_record(1000, 3, "notepad.exe", "C:\\notepad.exe", 10, 10),
        ];

        db.insert_traffic_batch(&records).unwrap();

        let top = db.top_consumers(0, 2000, 10).unwrap();
        assert_eq!(top.len(), 3);
        // firefox should be first (1000 total bytes).
        assert_eq!(top[0].process_name, "firefox.exe");
        assert_eq!(top[0].total_bytes, 1000);
        // chrome second (900 total bytes).
        assert_eq!(top[1].process_name, "chrome.exe");
        assert_eq!(top[1].total_bytes, 900);
        // notepad last (20 total bytes).
        assert_eq!(top[2].process_name, "notepad.exe");
        assert_eq!(top[2].total_bytes, 20);

        // Test limit.
        let top1 = db.top_consumers(0, 2000, 1).unwrap();
        assert_eq!(top1.len(), 1);
        assert_eq!(top1[0].process_name, "firefox.exe");
    }

    #[test]
    fn test_prune_old_records() {
        let db = open_memory_db();
        let now = chrono_timestamp();
        let old_ts = now - 100 * 86400; // 100 days ago
        let recent_ts = now - 86400; // 1 day ago

        let records = vec![
            make_record(old_ts, 1, "old.exe", "C:\\old.exe", 100, 100),
            make_record(old_ts + 5, 1, "old.exe", "C:\\old.exe", 200, 200),
            make_record(recent_ts, 2, "recent.exe", "C:\\recent.exe", 300, 300),
        ];

        db.insert_traffic_batch(&records).unwrap();

        // Prune records older than 90 days — should delete the 2 old records.
        let deleted = db.prune_old_records(90).unwrap();
        assert_eq!(deleted, 2);

        // Only the recent record should remain.
        let remaining = db.query_history(0, now + 1000, None).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].process_name, "recent.exe");
    }

    #[test]
    fn test_save_and_load_rules() {
        let db = open_memory_db();

        db.save_rule(
            "default",
            "C:\\chrome.exe",
            "chrome.exe",
            1_000_000,
            500_000,
            false,
        )
        .unwrap();
        db.save_rule(
            "default",
            "C:\\firefox.exe",
            "firefox.exe",
            2_000_000,
            1_000_000,
            true,
        )
        .unwrap();

        let rules = db.load_rules("default").unwrap();
        assert_eq!(rules.len(), 2);

        // Find chrome rule.
        let chrome_rule = rules
            .iter()
            .find(|r| r.exe_path == "C:\\chrome.exe")
            .unwrap();
        assert_eq!(chrome_rule.process_name, "chrome.exe");
        assert_eq!(chrome_rule.download_bps, 1_000_000);
        assert_eq!(chrome_rule.upload_bps, 500_000);
        assert!(!chrome_rule.blocked);

        // Find firefox rule.
        let firefox_rule = rules
            .iter()
            .find(|r| r.exe_path == "C:\\firefox.exe")
            .unwrap();
        assert_eq!(firefox_rule.process_name, "firefox.exe");
        assert_eq!(firefox_rule.download_bps, 2_000_000);
        assert_eq!(firefox_rule.upload_bps, 1_000_000);
        assert!(firefox_rule.blocked);

        // Loading rules for a non-existent profile returns empty.
        let empty = db.load_rules("nonexistent").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_list_profiles() {
        let db = open_memory_db();

        db.save_rule("gaming", "C:\\game.exe", "game.exe", 0, 0, false)
            .unwrap();
        db.save_rule("work", "C:\\slack.exe", "slack.exe", 0, 0, false)
            .unwrap();
        db.save_rule("gaming", "C:\\steam.exe", "steam.exe", 0, 0, false)
            .unwrap();

        let profiles = db.list_profiles().unwrap();
        assert_eq!(profiles.len(), 2);
        // Profiles are ordered alphabetically.
        assert!(profiles.contains(&"gaming".to_string()));
        assert!(profiles.contains(&"work".to_string()));
    }

    #[test]
    fn test_delete_profile() {
        let db = open_memory_db();

        db.save_rule("temp", "C:\\app.exe", "app.exe", 100, 200, false)
            .unwrap();
        db.save_rule("temp", "C:\\other.exe", "other.exe", 300, 400, true)
            .unwrap();

        // Verify the profile exists.
        let profiles = db.list_profiles().unwrap();
        assert!(profiles.contains(&"temp".to_string()));

        // Delete the profile.
        let deleted = db.delete_profile("temp").unwrap();
        assert_eq!(deleted, 2);

        // Profile should no longer appear.
        let profiles = db.list_profiles().unwrap();
        assert!(!profiles.contains(&"temp".to_string()));

        // Rules should be gone.
        let rules = db.load_rules("temp").unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn test_save_rule_upsert() {
        let db = open_memory_db();

        // Save a rule.
        db.save_rule(
            "default",
            "C:\\chrome.exe",
            "chrome.exe",
            1_000_000,
            500_000,
            false,
        )
        .unwrap();

        // Save again with updated values for the same profile + exe_path.
        db.save_rule(
            "default",
            "C:\\chrome.exe",
            "chrome.exe",
            2_000_000,
            750_000,
            true,
        )
        .unwrap();

        // Should still be one rule, not two (UNIQUE constraint + INSERT OR REPLACE).
        let rules = db.load_rules("default").unwrap();
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        assert_eq!(rule.exe_path, "C:\\chrome.exe");
        assert_eq!(rule.download_bps, 2_000_000);
        assert_eq!(rule.upload_bps, 750_000);
        assert!(rule.blocked);
    }
}
