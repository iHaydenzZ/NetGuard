//! Per-process traffic accounting using DashMap for lock-free concurrent access.
//!
//! Tracks bytes sent/received per PID, computes 1-second speed snapshots,
//! and provides snapshots for the frontend via Tauri events.

use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use serde::Serialize;

use tauri::Emitter;

use crate::core::process_mapper::ProcessMapper;

/// Running byte counters for a single process.
#[derive(Debug)]
pub struct TrafficCounters {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    prev_sent: u64,
    prev_recv: u64,
    last_tick: Option<Instant>,
    pub upload_speed: f64,
    pub download_speed: f64,
    pub connection_count: u32,
}

impl Default for TrafficCounters {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            bytes_recv: 0,
            prev_sent: 0,
            prev_recv: 0,
            last_tick: None,
            upload_speed: 0.0,
            download_speed: 0.0,
            connection_count: 0,
        }
    }
}

/// Snapshot of one process's traffic state, serializable for the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessTrafficSnapshot {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    /// Upload speed in bytes/sec.
    pub upload_speed: f64,
    /// Download speed in bytes/sec.
    pub download_speed: f64,
    /// Cumulative bytes sent since monitoring started.
    pub bytes_sent: u64,
    /// Cumulative bytes received since monitoring started.
    pub bytes_recv: u64,
    /// Number of active connections (TCP + UDP).
    pub connection_count: u32,
}

/// Thread-safe traffic tracker. Keyed by PID.
pub struct TrafficTracker {
    counters: DashMap<u32, TrafficCounters>,
}

impl TrafficTracker {
    pub fn new() -> Self {
        Self {
            counters: DashMap::new(),
        }
    }

    /// Record bytes for a process. Called from the capture loop.
    pub fn record_bytes(&self, pid: u32, sent: u64, recv: u64) {
        self.counters
            .entry(pid)
            .and_modify(|c| {
                c.bytes_sent += sent;
                c.bytes_recv += recv;
            })
            .or_insert_with(|| {
                let mut c = TrafficCounters::default();
                c.bytes_sent = sent;
                c.bytes_recv = recv;
                c
            });
    }

    /// Update connection counts from the process mapper.
    pub fn update_connection_counts(&self, mapper: &ProcessMapper) {
        let counts = mapper.connection_counts();
        for mut entry in self.counters.iter_mut() {
            let pid = *entry.key();
            entry.value_mut().connection_count =
                counts.get(&pid).map(|r| *r).unwrap_or(0);
        }
    }

    /// Recalculate speeds for all tracked processes. Call once per second.
    pub fn tick_speeds(&self) {
        let now = Instant::now();
        for mut entry in self.counters.iter_mut() {
            let c = entry.value_mut();
            if let Some(last) = c.last_tick {
                let elapsed = now.duration_since(last).as_secs_f64();
                if elapsed > 0.0 {
                    c.upload_speed = (c.bytes_sent.saturating_sub(c.prev_sent)) as f64 / elapsed;
                    c.download_speed =
                        (c.bytes_recv.saturating_sub(c.prev_recv)) as f64 / elapsed;
                }
            }
            c.prev_sent = c.bytes_sent;
            c.prev_recv = c.bytes_recv;
            c.last_tick = Some(now);
        }
    }

    /// Remove processes that have been idle (zero speed) for longer than `max_idle_secs`.
    pub fn remove_stale(&self, max_idle_secs: f64) {
        self.counters.retain(|_, c| {
            c.upload_speed > 0.0
                || c.download_speed > 0.0
                || c.last_tick
                    .map(|t| t.elapsed().as_secs_f64() < max_idle_secs)
                    .unwrap_or(true)
        });
    }

    /// Produce a snapshot of all tracked processes for the frontend.
    pub fn snapshot(&self, process_mapper: &ProcessMapper) -> Vec<ProcessTrafficSnapshot> {
        self.counters
            .iter()
            .map(|entry| {
                let pid = *entry.key();
                let c = entry.value();
                let info = process_mapper.get_process_info(pid);
                ProcessTrafficSnapshot {
                    pid,
                    name: info
                        .as_ref()
                        .map(|i| i.name.clone())
                        .unwrap_or_else(|| format!("PID {pid}")),
                    exe_path: info
                        .as_ref()
                        .map(|i| i.exe_path.clone())
                        .unwrap_or_default(),
                    upload_speed: c.upload_speed,
                    download_speed: c.download_speed,
                    bytes_sent: c.bytes_sent,
                    bytes_recv: c.bytes_recv,
                    connection_count: c.connection_count,
                }
            })
            .collect()
    }

    /// Spawn a stats aggregator thread that ticks speeds every 1s and emits events.
    /// Uses a plain OS thread to avoid requiring a Tokio runtime context at call site.
    pub fn start_aggregator(
        self: &Arc<Self>,
        process_mapper: Arc<ProcessMapper>,
        app_handle: tauri::AppHandle,
    ) {
        let tracker = Arc::clone(self);
        std::thread::Builder::new()
            .name("stats-aggregator".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    tracker.update_connection_counts(&process_mapper);
                    tracker.tick_speeds();
                    tracker.remove_stale(10.0);

                    let stats = tracker.snapshot(&process_mapper);
                    if let Err(e) = app_handle.emit("traffic-stats", &stats) {
                        tracing::warn!("Failed to emit traffic-stats: {e}");
                    }
                }
            })
            .expect("failed to spawn stats aggregator thread");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::process_mapper::ProcessMapper;
    use std::thread;
    use std::time::Duration;

    /// Helper: create a fresh ProcessMapper (empty — no system scan).
    fn empty_mapper() -> ProcessMapper {
        ProcessMapper::new()
    }

    #[test]
    fn test_new_tracker_empty() {
        let tracker = TrafficTracker::new();
        let mapper = empty_mapper();
        let snap = tracker.snapshot(&mapper);
        assert!(snap.is_empty(), "new tracker should produce an empty snapshot");
    }

    #[test]
    fn test_record_bytes_single() {
        let tracker = TrafficTracker::new();
        let mapper = empty_mapper();

        tracker.record_bytes(1, 100, 200);

        let snap = tracker.snapshot(&mapper);
        assert_eq!(snap.len(), 1);
        let entry = &snap[0];
        assert_eq!(entry.pid, 1);
        assert_eq!(entry.bytes_sent, 100);
        assert_eq!(entry.bytes_recv, 200);
    }

    #[test]
    fn test_record_bytes_accumulates() {
        let tracker = TrafficTracker::new();
        let mapper = empty_mapper();

        tracker.record_bytes(1, 100, 200);
        tracker.record_bytes(1, 50, 80);

        let snap = tracker.snapshot(&mapper);
        assert_eq!(snap.len(), 1);
        let entry = &snap[0];
        assert_eq!(entry.bytes_sent, 150, "bytes_sent should accumulate");
        assert_eq!(entry.bytes_recv, 280, "bytes_recv should accumulate");
    }

    #[test]
    fn test_record_bytes_multiple_pids() {
        let tracker = TrafficTracker::new();
        let mapper = empty_mapper();

        tracker.record_bytes(1, 100, 200);
        tracker.record_bytes(2, 300, 400);

        let snap = tracker.snapshot(&mapper);
        assert_eq!(snap.len(), 2, "should track two separate PIDs");

        // Collect by PID for deterministic assertions (DashMap iteration order is arbitrary).
        let mut by_pid: std::collections::HashMap<u32, &ProcessTrafficSnapshot> =
            snap.iter().map(|s| (s.pid, s)).collect();

        let p1 = by_pid.remove(&1).expect("PID 1 missing");
        assert_eq!(p1.bytes_sent, 100);
        assert_eq!(p1.bytes_recv, 200);

        let p2 = by_pid.remove(&2).expect("PID 2 missing");
        assert_eq!(p2.bytes_sent, 300);
        assert_eq!(p2.bytes_recv, 400);
    }

    #[test]
    fn test_tick_speeds_calculates() {
        let tracker = TrafficTracker::new();
        let mapper = empty_mapper();

        // Record initial bytes and establish baseline.
        tracker.record_bytes(1, 1000, 2000);
        tracker.tick_speeds();

        // Small sleep so the next tick has a nonzero elapsed time.
        thread::sleep(Duration::from_millis(50));

        // Record more bytes.
        tracker.record_bytes(1, 500, 600);
        tracker.tick_speeds();

        let snap = tracker.snapshot(&mapper);
        assert_eq!(snap.len(), 1);
        let entry = &snap[0];
        assert!(
            entry.upload_speed > 0.0,
            "upload_speed should be > 0 after second tick with new bytes"
        );
        assert!(
            entry.download_speed > 0.0,
            "download_speed should be > 0 after second tick with new bytes"
        );
    }

    #[test]
    fn test_tick_speeds_first_tick_zero() {
        let tracker = TrafficTracker::new();
        let mapper = empty_mapper();

        // Record some bytes, then tick once (first tick only establishes a baseline).
        tracker.record_bytes(1, 1000, 2000);
        tracker.tick_speeds();

        let snap = tracker.snapshot(&mapper);
        assert_eq!(snap.len(), 1);
        let entry = &snap[0];
        assert!(
            entry.upload_speed == 0.0,
            "upload_speed should be 0 on first tick (baseline only)"
        );
        assert!(
            entry.download_speed == 0.0,
            "download_speed should be 0 on first tick (baseline only)"
        );
    }

    #[test]
    fn test_remove_stale_keeps_active() {
        let tracker = TrafficTracker::new();
        let mapper = empty_mapper();

        tracker.record_bytes(1, 1000, 2000);
        tracker.tick_speeds();

        thread::sleep(Duration::from_millis(50));

        // Record more bytes so speed > 0 on next tick.
        tracker.record_bytes(1, 500, 600);
        tracker.tick_speeds();

        // Process has speed > 0, so it should survive remove_stale.
        tracker.remove_stale(10.0);

        let snap = tracker.snapshot(&mapper);
        assert_eq!(snap.len(), 1, "active process should not be removed");
    }

    #[test]
    fn test_remove_stale_removes_idle() {
        let tracker = TrafficTracker::new();
        let mapper = empty_mapper();

        // Record bytes and establish baseline.
        tracker.record_bytes(1, 1000, 2000);
        tracker.tick_speeds();

        thread::sleep(Duration::from_millis(50));

        // Tick again WITHOUT recording new bytes — speed drops to 0.
        tracker.tick_speeds();

        // Use a very small max_idle_secs so that last_tick elapsed > max_idle_secs.
        thread::sleep(Duration::from_millis(50));
        tracker.remove_stale(0.01);

        let snap = tracker.snapshot(&mapper);
        assert!(
            snap.is_empty(),
            "idle process should be removed when last_tick elapsed > max_idle_secs"
        );
    }

    #[test]
    fn test_snapshot_fallback_name() {
        let tracker = TrafficTracker::new();
        let mapper = empty_mapper();

        // PID 99999 is not in the mapper, so snapshot should use fallback name.
        tracker.record_bytes(99999, 10, 20);

        let snap = tracker.snapshot(&mapper);
        assert_eq!(snap.len(), 1);
        let entry = &snap[0];
        assert_eq!(entry.pid, 99999);
        assert_eq!(
            entry.name, "PID 99999",
            "unknown PID should have fallback name 'PID {{pid}}'"
        );
        assert_eq!(
            entry.exe_path, "",
            "unknown PID should have empty exe_path"
        );
    }
}
