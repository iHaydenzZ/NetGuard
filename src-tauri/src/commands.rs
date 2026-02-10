/// Tauri IPC command handlers.
/// All #[tauri::command] functions go here and are registered in lib.rs.
use std::collections::HashMap;
use std::sync::Arc;

use tauri::State;

use crate::core::process_mapper::ProcessMapper;
use crate::core::rate_limiter::{BandwidthLimit, RateLimiterManager};
use crate::core::traffic::{ProcessTrafficSnapshot, TrafficTracker};

/// Shared application state managed by Tauri.
pub struct AppState {
    pub process_mapper: Arc<ProcessMapper>,
    pub traffic_tracker: Arc<TrafficTracker>,
    pub rate_limiter: Arc<RateLimiterManager>,
}

/// Returns the current traffic snapshot for all monitored processes.
#[tauri::command]
pub fn get_traffic_stats(state: State<'_, AppState>) -> Vec<ProcessTrafficSnapshot> {
    state.traffic_tracker.snapshot(&state.process_mapper)
}

/// Set a bandwidth limit for a process.
/// `download_bps` and `upload_bps` are in bytes per second. 0 = unlimited for that direction.
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
