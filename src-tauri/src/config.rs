//! Centralized runtime constants for NetGuard.
//!
//! All tunable intervals, thresholds, and counts are collected here so they can
//! be found and adjusted in a single place rather than scattered across modules.

/// Interval at which the stats aggregator ticks speeds and emits events to the frontend (seconds).
pub const STATS_INTERVAL_SECS: u64 = 1;

/// Interval at which traffic snapshots are recorded to the SQLite history table (seconds).
pub const HISTORY_RECORD_INTERVAL_SECS: u64 = 5;

/// Interval at which the system tray tooltip, menu, and threshold notifications are updated (seconds).
pub const TRAY_UPDATE_INTERVAL_SECS: u64 = 2;

/// Interval at which persistent profile rules are auto-applied to newly launched processes (seconds).
pub const PERSISTENT_RULES_INTERVAL_SECS: u64 = 3;

/// Maximum age of traffic history records before they are pruned (days).
pub const PRUNE_MAX_AGE_DAYS: u64 = 90;

/// Number of history-recorder ticks between pruning checks.
/// At 5-second intervals, 17280 ticks ≈ 1 day (5 × 17280 = 86400 seconds).
pub const PRUNE_CHECK_INTERVAL_TICKS: u64 = 17280;

/// Processes with zero speed for longer than this are removed from the tracker (seconds).
pub const STALE_PROCESS_TIMEOUT_SECS: f64 = 10.0;

/// Number of top bandwidth consumers shown in the system tray menu.
pub const TRAY_TOP_CONSUMERS_COUNT: usize = 5;

/// Interval at which the process scanner refreshes PID ↔ port mappings (milliseconds).
pub const PROCESS_SCAN_INTERVAL_MS: u64 = 500;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prune_interval_approximates_one_day() {
        let total_secs = HISTORY_RECORD_INTERVAL_SECS * PRUNE_CHECK_INTERVAL_TICKS;
        assert_eq!(
            total_secs, 86400,
            "prune interval should equal one day in seconds"
        );
    }

    #[test]
    fn test_all_intervals_positive() {
        assert!(STATS_INTERVAL_SECS > 0);
        assert!(HISTORY_RECORD_INTERVAL_SECS > 0);
        assert!(TRAY_UPDATE_INTERVAL_SECS > 0);
        assert!(PERSISTENT_RULES_INTERVAL_SECS > 0);
        assert!(PRUNE_MAX_AGE_DAYS > 0);
        assert!(PRUNE_CHECK_INTERVAL_TICKS > 0);
        assert!(STALE_PROCESS_TIMEOUT_SECS > 0.0);
        assert!(TRAY_TOP_CONSUMERS_COUNT > 0);
        assert!(PROCESS_SCAN_INTERVAL_MS > 0);
    }
}
