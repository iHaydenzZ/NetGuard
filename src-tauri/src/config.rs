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

/// Hard cap on traffic_history rows; the oldest rows beyond it are deleted.
/// Backstop for the age-based prune (~100 bytes/row -> ~100 MB worst case).
pub const MAX_HISTORY_ROWS: u64 = 1_000_000;

/// Number of history-recorder ticks between row-cap checks.
/// At 5-second intervals, 720 ticks = 1 hour.
pub const HISTORY_CAP_CHECK_INTERVAL_TICKS: u64 = 720;

/// Processes with zero speed for longer than this are removed from the tracker (seconds).
pub const STALE_PROCESS_TIMEOUT_SECS: f64 = 10.0;

/// Number of top bandwidth consumers shown in the system tray menu.
pub const TRAY_TOP_CONSUMERS_COUNT: usize = 5;

/// Interval at which the process scanner refreshes PID ↔ port mappings (milliseconds).
pub const PROCESS_SCAN_INTERVAL_MS: u64 = 500;

/// Largest packet WinDivert can deliver (WINDIVERT_MTU_MAX in the WinDivert 2.2
/// bindings). Used both for recv buffer sizing (a truncated re-injected packet
/// would corrupt the connection) and as the token-bucket burst floor (a bucket
/// smaller than one packet becomes a permanent block instead of a throttle).
pub const WINDIVERT_MTU_MAX_BYTES: usize = 65_575;

/// Default WinDivert filter for BOTH SNIFF mode and the intercept default.
///
/// Parens are required: WinDivert grammar binds `and` tighter than `or`, so
/// `tcp or udp and not loopback` would parse as `tcp or (udp and not loopback)`,
/// silently leaving loopback TCP traffic captured.
///
/// Loopback is excluded so local IPC (DB connections, dev servers) is neither
/// counted nor throttled. Shared by `capture::windivert_backend::SNIFF_FILTER`
/// and `commands::logic::resolve_intercept_filter` — a divergence between the
/// two would make monitoring and enforcement see different traffic.
pub const DEFAULT_CAPTURE_FILTER: &str = "(tcp or udp) and not loopback";

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

    /// Compile-time sanity: all constants are positive.
    /// Uses const assertions to avoid clippy::assertions_on_constants.
    #[test]
    fn test_all_intervals_positive() {
        const _: () = assert!(STATS_INTERVAL_SECS > 0);
        const _: () = assert!(HISTORY_RECORD_INTERVAL_SECS > 0);
        const _: () = assert!(TRAY_UPDATE_INTERVAL_SECS > 0);
        const _: () = assert!(PERSISTENT_RULES_INTERVAL_SECS > 0);
        const _: () = assert!(PRUNE_MAX_AGE_DAYS > 0);
        const _: () = assert!(PRUNE_CHECK_INTERVAL_TICKS > 0);
        const _: () = assert!(TRAY_TOP_CONSUMERS_COUNT > 0);
        const _: () = assert!(PROCESS_SCAN_INTERVAL_MS > 0);
        const _: () = assert!(MAX_HISTORY_ROWS > 0);
        const _: () = assert!(HISTORY_CAP_CHECK_INTERVAL_TICKS > 0);
        // f64 cannot use const assert, so skip STALE_PROCESS_TIMEOUT_SECS
    }
}
