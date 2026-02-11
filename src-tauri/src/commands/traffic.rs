//! F1 traffic monitoring, F4 traffic history, and AC-1.6 process icon commands.

use tauri::State;

use crate::core::traffic::ProcessTrafficSnapshot;
use crate::db::{self, TrafficSummary};
use crate::error::AppError;

use super::state::AppState;

/// Returns the current traffic snapshot for all monitored processes.
#[tauri::command]
pub fn get_traffic_stats(
    state: State<'_, AppState>,
) -> Result<Vec<ProcessTrafficSnapshot>, AppError> {
    Ok(state.traffic_tracker.snapshot(&state.process_mapper))
}

/// Get the base64-encoded icon data URI for a process executable.
#[tauri::command]
pub fn get_process_icon(
    state: State<'_, AppState>,
    exe_path: String,
) -> Result<Option<String>, AppError> {
    Ok(state.process_mapper.get_icon_base64(&exe_path))
}

/// Query traffic history within a time range (unix timestamps in seconds).
#[tauri::command]
pub fn get_traffic_history(
    state: State<'_, AppState>,
    from_timestamp: i64,
    to_timestamp: i64,
    process_name: Option<String>,
) -> Result<Vec<db::TrafficRecord>, AppError> {
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
    state
        .database
        .top_consumers(from_timestamp, to_timestamp, limit)
        .map_err(|e| AppError::Database(e.to_string()))
}
