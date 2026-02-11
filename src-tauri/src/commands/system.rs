//! F6 notification threshold, F7 auto-start, and intercept mode commands.

use std::sync::Arc;

use tauri::State;

use crate::capture::CaptureEngine;
use crate::error::AppError;

use super::logic::{resolve_intercept_filter, validate_intercept_enable};
use super::state::AppState;

// ---- AC-6.4: Bandwidth Threshold Notifications ----

#[tauri::command]
pub fn set_notification_threshold(
    state: State<'_, AppState>,
    threshold_bps: u64,
) -> Result<(), AppError> {
    state
        .notification_threshold_bps
        .store(threshold_bps, std::sync::atomic::Ordering::Relaxed);
    tracing::info!("Notification threshold set to {threshold_bps} B/s");
    Ok(())
}

#[tauri::command]
pub fn get_notification_threshold(state: State<'_, AppState>) -> Result<u64, AppError> {
    Ok(state
        .notification_threshold_bps
        .load(std::sync::atomic::Ordering::Relaxed))
}

// ---- F7: Auto-Start ----

#[tauri::command]
pub fn set_autostart(enabled: bool) -> Result<(), AppError> {
    let exe = std::env::current_exe().map_err(|e| AppError::Io(e.to_string()))?;
    let exe_str = exe.to_string_lossy().to_string();
    let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

    if enabled {
        let output = std::process::Command::new("reg")
            .args([
                "add", key, "/v", "NetGuard", "/t", "REG_SZ", "/d", &exe_str, "/f",
            ])
            .output()
            .map_err(|e| AppError::Io(e.to_string()))?;
        if !output.status.success() {
            return Err(AppError::Io("Failed to add registry entry".into()));
        }
        tracing::info!("Auto-start enabled: {exe_str}");
    } else {
        let _ = std::process::Command::new("reg")
            .args(["delete", key, "/v", "NetGuard", "/f"])
            .output();
        tracing::info!("Auto-start disabled");
    }
    Ok(())
}

#[tauri::command]
pub fn get_autostart() -> Result<bool, AppError> {
    let output = std::process::Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "NetGuard",
        ])
        .output();
    Ok(matches!(output, Ok(o) if o.status.success()))
}

// ---- Phase 2: Intercept Mode ----

#[tauri::command]
pub fn enable_intercept_mode(
    state: State<'_, AppState>,
    filter: Option<String>,
) -> Result<(), AppError> {
    let mut intercept_guard = state.intercept_engine.lock().unwrap();
    validate_intercept_enable(intercept_guard.is_some())?;

    {
        let mut sniff_guard = state.sniff_engine.lock().unwrap();
        if sniff_guard.take().is_some() {
            tracing::info!("SNIFF engine stopped (switching to intercept)");
        }
    }

    let filter = resolve_intercept_filter(filter);
    tracing::info!("Enabling INTERCEPT mode with filter: {filter}");

    let engine = CaptureEngine::start_intercept(
        Arc::clone(&state.process_mapper),
        Arc::clone(&state.traffic_tracker),
        Arc::clone(&state.rate_limiter),
        filter,
    )
    .map_err(|e| AppError::Capture(e.to_string()))?;

    *intercept_guard = Some(engine);
    Ok(())
}

#[tauri::command]
pub fn disable_intercept_mode(state: State<'_, AppState>) -> Result<(), AppError> {
    {
        let mut intercept_guard = state.intercept_engine.lock().unwrap();
        if intercept_guard.take().is_some() {
            tracing::info!("INTERCEPT engine stopped");
        }
    }

    match CaptureEngine::start_sniff(
        Arc::clone(&state.process_mapper),
        Arc::clone(&state.traffic_tracker),
    ) {
        Ok(engine) => {
            *state.sniff_engine.lock().unwrap() = Some(engine);
            tracing::info!("SNIFF mode restarted after disabling intercept");
        }
        Err(e) => {
            tracing::warn!("Failed to restart SNIFF mode: {e:#}");
        }
    }

    Ok(())
}

#[tauri::command]
pub fn is_intercept_active(state: State<'_, AppState>) -> Result<bool, AppError> {
    Ok(state.intercept_engine.lock().unwrap().is_some())
}
