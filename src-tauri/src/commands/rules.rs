//! F2 bandwidth limiting, F3 connection blocking, and F5 rule profile commands.

use std::collections::HashMap;

use tauri::State;

use crate::core::BandwidthLimit;
use crate::db;
use crate::error::AppError;

use super::logic::{build_profile_rules, match_rules_to_processes, ApplyAction};
use super::state::AppState;

// ---- F2: Bandwidth Limiting ----

#[tauri::command]
pub fn set_bandwidth_limit(
    state: State<'_, AppState>,
    pid: u32,
    download_bps: u64,
    upload_bps: u64,
) -> Result<(), AppError> {
    state.rate_limiter.set_limit(pid, BandwidthLimit { download_bps, upload_bps });
    tracing::info!("Set bandwidth limit for PID {pid}: DL={download_bps} B/s, UL={upload_bps} B/s");
    Ok(())
}

#[tauri::command]
pub fn remove_bandwidth_limit(state: State<'_, AppState>, pid: u32) -> Result<(), AppError> {
    state.rate_limiter.remove_limit(pid);
    tracing::info!("Removed bandwidth limit for PID {pid}");
    Ok(())
}

#[tauri::command]
pub fn get_bandwidth_limits(
    state: State<'_, AppState>,
) -> Result<HashMap<u32, BandwidthLimit>, AppError> {
    Ok(state.rate_limiter.get_all_limits())
}

// ---- F3: Connection Blocking ----

#[tauri::command]
pub fn block_process(state: State<'_, AppState>, pid: u32) -> Result<(), AppError> {
    state.rate_limiter.block_process(pid);
    tracing::info!("Blocked PID {pid}");
    Ok(())
}

#[tauri::command]
pub fn unblock_process(state: State<'_, AppState>, pid: u32) -> Result<(), AppError> {
    state.rate_limiter.unblock_process(pid);
    tracing::info!("Unblocked PID {pid}");
    Ok(())
}

#[tauri::command]
pub fn get_blocked_pids(state: State<'_, AppState>) -> Result<Vec<u32>, AppError> {
    Ok(state.rate_limiter.get_blocked_pids())
}

// ---- F5: Rule Profiles ----

#[tauri::command]
pub fn save_profile(state: State<'_, AppState>, profile_name: String) -> Result<(), AppError> {
    let limits = state.rate_limiter.get_all_limits();
    let blocked_pids = state.rate_limiter.get_blocked_pids();
    let snapshot = state.traffic_tracker.snapshot(&state.process_mapper);
    let rules = build_profile_rules(&limits, &blocked_pids, &snapshot);

    for rule in &rules {
        state
            .database
            .save_rule(
                &profile_name,
                &rule.exe_path,
                &rule.process_name,
                rule.download_bps,
                rule.upload_bps,
                rule.blocked,
            )
            .map_err(|e| AppError::Database(e.to_string()))?;
    }

    tracing::info!("Saved profile '{profile_name}' with {} rules", rules.len());
    Ok(())
}

#[tauri::command]
pub fn apply_profile(state: State<'_, AppState>, profile_name: String) -> Result<usize, AppError> {
    let rules = state
        .database
        .load_rules(&profile_name)
        .map_err(|e| AppError::Database(e.to_string()))?;

    state.rate_limiter.clear_all();
    *state.persistent_rules.lock().unwrap() = rules.clone();

    let snapshot = state.traffic_tracker.snapshot(&state.process_mapper);
    let actions = match_rules_to_processes(&rules, &snapshot);

    for action in &actions {
        match action {
            ApplyAction::Block { pid } => state.rate_limiter.block_process(*pid),
            ApplyAction::Limit { pid, download_bps, upload_bps } => {
                state.rate_limiter.set_limit(
                    *pid,
                    BandwidthLimit { download_bps: *download_bps, upload_bps: *upload_bps },
                );
            }
        }
    }

    tracing::info!(
        "Applied profile '{profile_name}': {}/{} rules matched",
        actions.len(),
        rules.len()
    );
    Ok(actions.len())
}

#[tauri::command]
pub fn list_profiles(state: State<'_, AppState>) -> Result<Vec<String>, AppError> {
    state.database.list_profiles().map_err(|e| AppError::Database(e.to_string()))
}

#[tauri::command]
pub fn delete_profile(state: State<'_, AppState>, profile_name: String) -> Result<(), AppError> {
    state
        .database
        .delete_profile(&profile_name)
        .map_err(|e| AppError::Database(e.to_string()))?;
    tracing::info!("Deleted profile '{profile_name}'");
    Ok(())
}

#[tauri::command]
pub fn get_profile_rules(
    state: State<'_, AppState>,
    profile_name: String,
) -> Result<Vec<db::SavedRule>, AppError> {
    state.database.load_rules(&profile_name).map_err(|e| AppError::Database(e.to_string()))
}
