//! F1 traffic monitoring, F4 traffic history, and AC-1.6 process icon commands.

use tauri::State;

use crate::core::ProcessTrafficSnapshot;
use crate::db::{self, TrafficSummary};
use crate::error::AppError;

use super::logic::{validate_icon_exe_path, validate_icon_request_pid, validate_timestamps};
use super::state::AppState;

/// Maximum number of top consumers that can be requested.
const MAX_TOP_CONSUMERS_LIMIT: usize = 100;

/// Returns the current traffic snapshot for all monitored processes.
#[tauri::command]
pub fn get_traffic_stats(
    state: State<'_, AppState>,
) -> Result<Vec<ProcessTrafficSnapshot>, AppError> {
    Ok(state.traffic_tracker.snapshot(&state.process_mapper))
}

/// Get the base64-encoded icon data URI for a process, identified by PID.
///
/// The renderer passes a PID; the backend resolves the exe path from
/// ProcessMapper so the IPC surface never accepts an arbitrary filesystem path.
///
/// Returns `Ok(None)` for unknown PIDs (process may be mid-registration) and
/// for paths that fail internal validation — icon extraction is cosmetic and
/// "no icon" is always a safe fallback. Returns `Err` only for reserved PIDs
/// (PID 0, 4, NetGuard itself) to signal a caller logic error.
#[tauri::command]
pub fn get_process_icon(state: State<'_, AppState>, pid: u32) -> Result<Option<String>, AppError> {
    validate_icon_request_pid(pid)?;
    let Some(info) = state.process_mapper.get_process_info(pid) else {
        // Unknown PID: process may be mid-registration; not a caller fault.
        return Ok(None);
    };
    // Path comes from our own mapper, so a bad value is data quality, not
    // caller input — return Ok(None) rather than an error.
    if validate_icon_exe_path(&info.exe_path).is_err() {
        tracing::debug!(pid, exe_path = %info.exe_path, "Skipping icon for invalid exe path from mapper");
        return Ok(None);
    }
    Ok(state.process_mapper.get_icon_base64(&info.exe_path))
}

/// Query traffic history within a time range (unix timestamps in seconds).
#[tauri::command]
pub fn get_traffic_history(
    state: State<'_, AppState>,
    from_timestamp: i64,
    to_timestamp: i64,
    process_name: Option<String>,
) -> Result<Vec<db::TrafficRecord>, AppError> {
    validate_timestamps(from_timestamp, to_timestamp)?;
    state
        .database
        .query_history(from_timestamp, to_timestamp, process_name.as_deref())
        .map_err(|e| AppError::Database(e.to_string()))
}

/// Get top bandwidth consumers over a time window.
#[tauri::command]
pub fn get_top_consumers(
    state: State<'_, AppState>,
    from_timestamp: i64,
    to_timestamp: i64,
    limit: usize,
) -> Result<Vec<TrafficSummary>, AppError> {
    validate_timestamps(from_timestamp, to_timestamp)?;
    let limit = limit.min(MAX_TOP_CONSUMERS_LIMIT);
    state
        .database
        .top_consumers(from_timestamp, to_timestamp, limit)
        .map_err(|e| AppError::Database(e.to_string()))
}
