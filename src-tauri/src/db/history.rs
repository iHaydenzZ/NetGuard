//! Traffic history table CRUD operations.

use anyhow::Result;
use rusqlite::params;

use super::{chrono_timestamp, Database, TrafficRecord, TrafficSummary};

impl Database {
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

#[cfg(test)]
mod tests {
    use super::super::tests::{make_record, open_memory_db};
    use super::*;

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
}
