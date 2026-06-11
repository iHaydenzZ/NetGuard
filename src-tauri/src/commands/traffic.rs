//! F1 traffic monitoring, F4 traffic history, and AC-1.6 process icon commands.

use serde::Serialize;
use tauri::State;
use ts_rs::TS;

use crate::core::ProcessTrafficSnapshot;
use crate::db::{self, TrafficSummary};
use crate::error::AppError;

use super::logic::{validate_icon_exe_path, validate_icon_request_pid, validate_timestamps};
use super::state::AppState;

/// Maximum number of top consumers that can be requested.
const MAX_TOP_CONSUMERS_LIMIT: usize = 100;

/// Default number of aggregated points returned by `get_traffic_history` when
/// the caller does not specify `max_points`. Comfortably above the pixel width
/// of any chart while keeping the IPC payload small.
const DEFAULT_HISTORY_MAX_POINTS: usize = 2_000;

/// Hard cap on aggregated points, enforced even if a caller requests more. A
/// 90-day history at 5s granularity is ~1.5M raw rows; this bounds the renderer
/// payload to a few thousand points regardless of caller input (clamped, not an
/// error).
const MAX_HISTORY_MAX_POINTS: usize = 10_000;

/// Returns the current traffic snapshot for all monitored processes.
#[tauri::command]
pub fn get_traffic_stats(
    state: State<'_, AppState>,
) -> Result<Vec<ProcessTrafficSnapshot>, AppError> {
    Ok(state.traffic_tracker.snapshot(&state.process_mapper))
}

/// A process icon plus the exe path the backend resolved the PID to.
///
/// PIDs can be reused between the renderer's traffic snapshot and the icon
/// request; echoing the resolved path lets the renderer detect that race and
/// cache the icon under the executable it actually belongs to, instead of
/// permanently mislabeling the snapshot's exe.
#[derive(Debug, Clone, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings.ts")]
pub struct ProcessIcon {
    /// Exe path the PID resolved to at extraction time.
    pub exe_path: String,
    /// Base64-encoded BMP data URI.
    pub icon: String,
}

/// Get the icon for a process, identified by PID.
///
/// The renderer passes a PID; the backend resolves the exe path from
/// ProcessMapper so the IPC surface never accepts an arbitrary filesystem path.
/// The resolved path is returned alongside the icon (see [`ProcessIcon`]).
///
/// Returns `Ok(None)` for unknown PIDs (process may be mid-registration) and
/// for paths that fail internal validation — icon extraction is cosmetic and
/// "no icon" is always a safe fallback. Returns `Err` only for reserved PIDs
/// (PID 0, 4, NetGuard itself) to signal a caller logic error.
#[tauri::command]
pub fn get_process_icon(
    state: State<'_, AppState>,
    pid: u32,
) -> Result<Option<ProcessIcon>, AppError> {
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
    Ok(state
        .process_mapper
        .get_icon_base64(&info.exe_path)
        .map(|icon| ProcessIcon {
            exe_path: info.exe_path,
            icon,
        }))
}

/// Query traffic history within a time range (unix timestamps in seconds).
///
/// Results are server-side aggregated into at most `max_points` time buckets so
/// the renderer never receives an unbounded number of rows. `max_points`
/// defaults to [`DEFAULT_HISTORY_MAX_POINTS`] and is clamped to
/// [`MAX_HISTORY_MAX_POINTS`] (overflow is clamped, not rejected). See
/// [`db::Database::query_history_aggregated`] for the aggregation contract.
#[tauri::command]
pub fn get_traffic_history(
    state: State<'_, AppState>,
    from_timestamp: i64,
    to_timestamp: i64,
    process_name: Option<String>,
    max_points: Option<usize>,
) -> Result<Vec<db::TrafficRecord>, AppError> {
    validate_timestamps(from_timestamp, to_timestamp)?;
    let max_points = max_points
        .unwrap_or(DEFAULT_HISTORY_MAX_POINTS)
        .clamp(1, MAX_HISTORY_MAX_POINTS);
    state
        .database
        .query_history_aggregated(
            from_timestamp,
            to_timestamp,
            process_name.as_deref(),
            max_points,
        )
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
