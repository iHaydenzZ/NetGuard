/// Tauri IPC command handlers.
/// All #[tauri::command] functions go here and are registered in lib.rs.
use std::collections::HashMap;
use std::sync::Arc;

use tauri::State;

use crate::core::process_mapper::ProcessMapper;
use crate::core::rate_limiter::{BandwidthLimit, RateLimiterManager};
use crate::core::traffic::{ProcessTrafficSnapshot, TrafficTracker};
use crate::db::{self, Database, TrafficSummary};

/// Shared application state managed by Tauri.
pub struct AppState {
    pub process_mapper: Arc<ProcessMapper>,
    pub traffic_tracker: Arc<TrafficTracker>,
    pub rate_limiter: Arc<RateLimiterManager>,
    pub database: Arc<Database>,
}

// ---- F1: Traffic Monitoring ----

/// Returns the current traffic snapshot for all monitored processes.
#[tauri::command]
pub fn get_traffic_stats(state: State<'_, AppState>) -> Vec<ProcessTrafficSnapshot> {
    state.traffic_tracker.snapshot(&state.process_mapper)
}

// ---- F2: Bandwidth Limiting ----

/// Set a bandwidth limit for a process.
#[tauri::command]
pub fn set_bandwidth_limit(
    state: State<'_, AppState>,
    pid: u32,
    download_bps: u64,
    upload_bps: u64,
) {
    state.rate_limiter.set_limit(
        pid,
        BandwidthLimit {
            download_bps,
            upload_bps,
        },
    );
    tracing::info!(
        "Set bandwidth limit for PID {pid}: DL={download_bps} B/s, UL={upload_bps} B/s"
    );
}

/// Remove the bandwidth limit for a process.
#[tauri::command]
pub fn remove_bandwidth_limit(state: State<'_, AppState>, pid: u32) {
    state.rate_limiter.remove_limit(pid);
    tracing::info!("Removed bandwidth limit for PID {pid}");
}

/// Get all current bandwidth limit configurations.
#[tauri::command]
pub fn get_bandwidth_limits(state: State<'_, AppState>) -> HashMap<u32, BandwidthLimit> {
    state.rate_limiter.get_all_limits()
}

// ---- F3: Connection Blocking ----

/// Block all network traffic for a process.
#[tauri::command]
pub fn block_process(state: State<'_, AppState>, pid: u32) {
    state.rate_limiter.block_process(pid);
    tracing::info!("Blocked PID {pid}");
}

/// Unblock a process, restoring network access.
#[tauri::command]
pub fn unblock_process(state: State<'_, AppState>, pid: u32) {
    state.rate_limiter.unblock_process(pid);
    tracing::info!("Unblocked PID {pid}");
}

/// Get all blocked PIDs.
#[tauri::command]
pub fn get_blocked_pids(state: State<'_, AppState>) -> Vec<u32> {
    state.rate_limiter.get_blocked_pids()
}

// ---- F4: Traffic History ----

/// Query traffic history within a time range (unix timestamps in seconds).
#[tauri::command]
pub fn get_traffic_history(
    state: State<'_, AppState>,
    from_timestamp: i64,
    to_timestamp: i64,
    process_name: Option<String>,
) -> Result<Vec<db::TrafficRecord>, String> {
    state
        .database
        .query_history(from_timestamp, to_timestamp, process_name.as_deref())
        .map_err(|e| e.to_string())
}

/// Get top bandwidth consumers over a time window.
#[tauri::command]
pub fn get_top_consumers(
    state: State<'_, AppState>,
    from_timestamp: i64,
    to_timestamp: i64,
    limit: usize,
) -> Result<Vec<TrafficSummary>, String> {
    state
        .database
        .top_consumers(from_timestamp, to_timestamp, limit)
        .map_err(|e| e.to_string())
}
