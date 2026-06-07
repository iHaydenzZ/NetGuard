//! Traffic history table CRUD operations.

use anyhow::Result;
use rusqlite::params;

use super::{chrono_timestamp, Database, TrafficRecord, TrafficSummary};

impl Database {
    /// Insert a batch of traffic snapshots (called every 5 seconds).
    pub fn insert_traffic_batch(&self, records: &[TrafficRecord]) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch("BEGIN")?;
        let result = (|| {
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
        })();
        match &result {
            Ok(()) => conn.execute_batch("COMMIT")?,
            Err(_) => {
                let _ = conn.execute_batch("ROLLBACK");
            }
        }
        result
    }

    /// Query traffic history within a time range, returning one row per stored
    /// (timestamp, PID) sample (unaggregated).
    ///
    /// Production callers use [`Database::query_history_aggregated`] to bound the
    /// result size; this unaggregated primitive is retained for tests and as a
    /// reference for the per-sample storage semantics the aggregation collapses.
    #[cfg(test)]
    pub fn query_history(
        &self,
        from_timestamp: i64,
        to_timestamp: i64,
        process_name: Option<&str>,
    ) -> Result<Vec<TrafficRecord>> {
        let conn = self.conn.lock();

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

    /// Query traffic history aggregated into at most `max_points` time buckets.
    ///
    /// Unlike [`query_history`], which returns one row per stored
    /// (timestamp, PID) sample and can hand the renderer millions of rows on a
    /// long-running install (5s sampling x 90-day retention), this method bounds
    /// the result to `max_points` rows while preserving the full time range.
    ///
    /// # Bucketing
    /// The range `[from, to]` is divided into fixed-width buckets. Bucket width
    /// is `ceil((to - from) / max_points)` (clamped to >= 1), so the bucket index
    /// `(timestamp - from) / width` never exceeds `max_points - 1` — the result
    /// is always at most `max_points` rows. Each returned row's `timestamp` is the
    /// bucket *start*: `from + bucket_index * width`. Buckets with no samples are
    /// omitted (no zero-filling). Rows are ordered by timestamp ascending.
    ///
    /// # Aggregation contract
    /// The chart sums per-process traffic to show total throughput over time, so
    /// aggregation mirrors that:
    /// - **`upload_speed` / `download_speed`** are instantaneous rates. Within a
    ///   bucket they are first SUMmed across all processes sharing a timestamp
    ///   (concurrent processes' rates add to the real wire rate at that instant),
    ///   then AVGeraged over the distinct timestamps in the bucket. A process
    ///   filter narrows this to the single process.
    /// - **`bytes_sent` / `bytes_recv`** are SESSION-CUMULATIVE counters that
    ///   reset when a PID restarts. Per process, the bucket's representative value
    ///   is the MAX (the final cumulative value seen in the window); these
    ///   per-process maxima are then SUMmed across processes. Cross-PID-restart
    ///   artifacts are inherent to the schema, same as the unaggregated query.
    /// - **`pid` / `process_name` / `exe_path`** are not meaningful for a bucket
    ///   that collapses multiple processes, so they are set to `0` / `""`. The
    ///   chart does not read these fields. (With a process filter every bucket
    ///   belongs to one process, but the fields are still cleared for a uniform
    ///   shape — callers needing per-process detail use [`query_history`].)
    pub fn query_history_aggregated(
        &self,
        from_timestamp: i64,
        to_timestamp: i64,
        process_name: Option<&str>,
        max_points: usize,
    ) -> Result<Vec<TrafficRecord>> {
        // Bucket width: ceil(range / max_points), clamped to >= 1 so that
        // degenerate ranges (from == to) and tiny ranges still produce one
        // bucket and never divide by zero.
        let max_points = max_points.max(1) as i64;
        let range = to_timestamp - from_timestamp;
        // Ceiling division: ceil(range / max_points). `div_ceil` for signed
        // integers is not stable on the MSRV (1.75), so compute it manually.
        // `range >= 0` (validated upstream) and `max_points >= 1`, so this is safe.
        let width = ((range + max_points - 1) / max_points).max(1);

        let conn = self.conn.lock();

        // Two CTEs because the two metric families need different inner
        // groupings before the outer per-bucket fold:
        //   per_proc: per (bucket, pid) MAX cumulative bytes  -> outer SUM
        //   per_ts:   per (bucket, timestamp) SUM of speeds   -> outer AVG
        // The bucket index is `(timestamp - ?from) / ?width`.
        let filter_clause = if process_name.is_some() {
            "AND process_name = ?4"
        } else {
            ""
        };
        let sql = format!(
            "WITH per_proc AS (
                 SELECT (timestamp - ?1) / ?3 AS bucket,
                        MAX(bytes_sent) AS max_sent,
                        MAX(bytes_recv) AS max_recv
                 FROM traffic_history
                 WHERE timestamp >= ?1 AND timestamp <= ?2 {filter_clause}
                 GROUP BY bucket, pid
             ),
             per_ts AS (
                 SELECT (timestamp - ?1) / ?3 AS bucket,
                        SUM(upload_speed) AS ts_up,
                        SUM(download_speed) AS ts_down
                 FROM traffic_history
                 WHERE timestamp >= ?1 AND timestamp <= ?2 {filter_clause}
                 GROUP BY bucket, timestamp
             ),
             bytes_agg AS (
                 SELECT bucket, SUM(max_sent) AS bytes_sent, SUM(max_recv) AS bytes_recv
                 FROM per_proc GROUP BY bucket
             ),
             speed_agg AS (
                 SELECT bucket, AVG(ts_up) AS upload_speed, AVG(ts_down) AS download_speed
                 FROM per_ts GROUP BY bucket
             )
             SELECT ?1 + bytes_agg.bucket * ?3 AS bucket_ts,
                    bytes_agg.bytes_sent,
                    bytes_agg.bytes_recv,
                    speed_agg.upload_speed,
                    speed_agg.download_speed
             FROM bytes_agg JOIN speed_agg USING (bucket)
             ORDER BY bucket ASC"
        );

        let mut stmt = conn.prepare_cached(&sql)?;

        let map_row = |row: &rusqlite::Row| -> rusqlite::Result<TrafficRecord> {
            Ok(TrafficRecord {
                timestamp: row.get(0)?,
                pid: 0,
                process_name: String::new(),
                exe_path: String::new(),
                bytes_sent: row.get(1)?,
                bytes_recv: row.get(2)?,
                upload_speed: row.get(3)?,
                download_speed: row.get(4)?,
            })
        };

        let rows = if let Some(name) = process_name {
            stmt.query_map(params![from_timestamp, to_timestamp, width, name], map_row)?
        } else {
            stmt.query_map(params![from_timestamp, to_timestamp, width], map_row)?
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
        let conn = self.conn.lock();
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
        let conn = self.conn.lock();
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

#[cfg(test)]
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
    fn test_query_history_aggregates_to_max_points() {
        let db = open_memory_db();
        // 100 records, one PID, ts 1000..=1099, speeds == i, cumulative bytes == i.
        let records: Vec<_> = (0..100)
            .map(|i| {
                make_record(
                    1000 + i,
                    1,
                    "chrome.exe",
                    r"C:\chrome.exe",
                    i as u64,
                    i as u64,
                )
            })
            .collect();
        db.insert_traffic_batch(&records).unwrap();

        let results = db.query_history_aggregated(1000, 1099, None, 10).unwrap();

        // Bound: never more than max_points rows.
        assert!(results.len() <= 10, "got {} rows", results.len());
        // First bucket starts at `from`.
        assert_eq!(results.first().unwrap().timestamp, 1000);

        // Value correctness. range = 99, width = ceil(99/10) = 10.
        // Bucket 0 spans ts 1000..=1009 -> i = 0..=9.
        //   speeds avg = mean(0..=9) = 4.5 (single PID, so per-ts sum == speed).
        //   cumulative bytes = MAX over bucket = 9 (single PID).
        let b0 = &results[0];
        assert_eq!(b0.timestamp, 1000);
        assert_eq!(b0.upload_speed, 4.5);
        assert_eq!(b0.download_speed, 4.5);
        assert_eq!(b0.bytes_sent, 9);
        assert_eq!(b0.bytes_recv, 9);

        // Bucket 9 spans ts 1090..=1099 -> i = 90..=99.
        //   speeds avg = mean(90..=99) = 94.5.
        //   cumulative bytes = MAX = 99.
        let last = results.last().unwrap();
        assert_eq!(last.timestamp, 1090);
        assert_eq!(last.upload_speed, 94.5);
        assert_eq!(last.bytes_sent, 99);
    }

    #[test]
    fn test_query_history_aggregated_sums_speeds_across_processes() {
        let db = open_memory_db();
        // Two processes active at the same timestamps within one bucket.
        // With from=0,to=9,max_points=1 the whole range collapses to one bucket.
        let records = vec![
            // ts 0: chrome up=10 down=20 cum_sent=100 cum_recv=200
            make_record(0, 1, "chrome.exe", r"C:\chrome.exe", 100, 200),
            // ts 0: firefox up=5 down=7 cum_sent=50 cum_recv=70
            make_record(0, 2, "firefox.exe", r"C:\firefox.exe", 50, 70),
            // ts 5: chrome up=30 down=40 cum_sent=300 cum_recv=400
            make_record(5, 1, "chrome.exe", r"C:\chrome.exe", 300, 400),
        ];
        // make_record sets upload_speed = bytes_sent, download_speed = bytes_recv.
        db.insert_traffic_batch(&records).unwrap();

        let results = db.query_history_aggregated(0, 9, None, 1).unwrap();
        assert_eq!(results.len(), 1);
        let b = &results[0];
        assert_eq!(b.timestamp, 0);

        // Speeds: per-timestamp SUM across processes, then AVG over distinct timestamps.
        //   ts 0 total up = 100 + 50 = 150; ts 5 total up = 300.
        //   avg = (150 + 300) / 2 = 225.
        assert_eq!(b.upload_speed, 225.0);
        //   ts 0 total down = 200 + 70 = 270; ts 5 total down = 400.
        //   avg = (270 + 400) / 2 = 335.
        assert_eq!(b.download_speed, 335.0);

        // Cumulative bytes: per-process MAX within bucket, then SUM across processes.
        //   chrome MAX sent = 300, firefox MAX sent = 50 -> 350.
        assert_eq!(b.bytes_sent, 350);
        //   chrome MAX recv = 400, firefox MAX recv = 70 -> 470.
        assert_eq!(b.bytes_recv, 470);
    }

    #[test]
    fn test_query_history_aggregated_degenerate_ranges() {
        let db = open_memory_db();
        db.insert_traffic_batch(&[
            make_record(1000, 1, "a.exe", r"C:\a.exe", 10, 20),
            make_record(1000, 1, "a.exe", r"C:\a.exe", 30, 40),
        ])
        .unwrap();

        // from == to: width clamps to 1, single bucket.
        let same = db.query_history_aggregated(1000, 1000, None, 10).unwrap();
        assert_eq!(same.len(), 1);
        assert_eq!(same[0].timestamp, 1000);

        // Empty range result.
        let empty = db.query_history_aggregated(5000, 6000, None, 10).unwrap();
        assert!(empty.is_empty());

        // max_points larger than range still works and is bounded.
        let many = db.query_history_aggregated(1000, 1000, None, 5000).unwrap();
        assert_eq!(many.len(), 1);
    }

    #[test]
    fn test_query_history_aggregated_with_process_filter() {
        let db = open_memory_db();
        db.insert_traffic_batch(&[
            make_record(0, 1, "chrome.exe", r"C:\chrome.exe", 100, 200),
            make_record(0, 2, "firefox.exe", r"C:\firefox.exe", 50, 70),
        ])
        .unwrap();

        let chrome = db
            .query_history_aggregated(0, 9, Some("chrome.exe"), 1)
            .unwrap();
        assert_eq!(chrome.len(), 1);
        // Only chrome contributes.
        assert_eq!(chrome[0].upload_speed, 100.0);
        assert_eq!(chrome[0].bytes_sent, 100);
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
