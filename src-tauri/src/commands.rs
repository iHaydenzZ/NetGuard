/// Tauri IPC command handlers.
/// All #[tauri::command] functions go here and are registered in lib.rs.
use std::sync::Arc;

use tauri::State;

use crate::core::process_mapper::ProcessMapper;
use crate::core::traffic::{ProcessTrafficSnapshot, TrafficTracker};

/// Shared application state managed by Tauri.
pub struct AppState {
    pub process_mapper: Arc<ProcessMapper>,
    pub traffic_tracker: Arc<TrafficTracker>,
}

/// Returns the current traffic snapshot for all monitored processes.
#[tauri::command]
pub fn get_traffic_stats(state: State<'_, AppState>) -> Vec<ProcessTrafficSnapshot> {
    state
        .traffic_tracker
        .snapshot(&state.process_mapper)
}
