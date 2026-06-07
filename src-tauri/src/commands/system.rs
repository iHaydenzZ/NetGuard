//! F6 notification threshold, F7 auto-start, and intercept mode commands.

use std::sync::Arc;

use tauri::{AppHandle, Emitter, Manager, State};

use crate::capture::CaptureEngine;
use crate::error::AppError;

use super::logic::{resolve_intercept_filter, validate_intercept_enable};
use super::state::AppState;

/// Tauri event emitted to the frontend when the intercept loop unexpectedly
/// dies and the app fails open (handle dropped, SNIFF restarted). The frontend
/// uses this to flip `interceptActive` back to false.
pub const INTERCEPT_FAILED_OPEN_EVENT: &str = "intercept-failed-open";

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
    app: AppHandle,
    state: State<'_, AppState>,
    filter: Option<String>,
) -> Result<(), AppError> {
    let mut intercept_guard = state.intercept_engine.lock();
    validate_intercept_enable(intercept_guard.is_some())?;

    {
        let mut sniff_guard = state.sniff_engine.lock();
        if sniff_guard.take().is_some() {
            tracing::info!("SNIFF engine stopped (switching to intercept)");
        }
    }

    #[cfg(not(debug_assertions))]
    if filter.is_some() {
        return Err(AppError::InvalidInput(
            "Custom intercept filters are debug-only".into(),
        ));
    }

    let filter = resolve_intercept_filter(filter)?;
    tracing::info!("Enabling INTERCEPT mode with filter: {filter}");

    // Recovery callback: runs on the intercept capture thread iff the loop dies
    // from an unknown recv error (fail-open). It must NOT drop the engine (and
    // thus join its own thread) synchronously, so it spawns a detached recovery
    // thread. The intentional-disable path uses WinDivertShutdown and never
    // invokes this callback, so there is no spurious restart on clean teardown.
    let recovery_app = app.clone();
    let on_unexpected_exit = Box::new(move || {
        let _ = std::thread::Builder::new()
            .name("intercept-recovery".into())
            .spawn(move || recover_from_intercept_failure(recovery_app));
    });

    let engine = CaptureEngine::start_intercept(
        Arc::clone(&state.process_mapper),
        Arc::clone(&state.traffic_tracker),
        Arc::clone(&state.rate_limiter),
        filter,
        on_unexpected_exit,
    )
    .map_err(|e| AppError::Capture(e.to_string()))?;

    *intercept_guard = Some(engine);
    Ok(())
}

/// Restore monitoring after the intercept loop unexpectedly died (fail-open).
///
/// Runs on a detached recovery thread (NOT the dead capture thread) so dropping
/// the dead `CaptureEngine` can safely join the exiting capture thread. Steps:
/// 1. Take and drop the dead intercept engine.
/// 2. Restart SNIFF so monitoring continues (only if not already running).
/// 3. Emit `INTERCEPT_FAILED_OPEN_EVENT` so the UI flips `interceptActive` off.
///
/// If the intercept engine was already cleared (e.g. an intentional disable
/// raced ahead), recovery becomes a no-op — the disable path already restored
/// SNIFF and there is nothing unexpected to report.
fn recover_from_intercept_failure(app: AppHandle) {
    let state = app.state::<AppState>();

    // Take the dead engine, then release the lock BEFORE dropping it: the engine's
    // Drop joins the (now-exiting) capture thread, and we must not hold the
    // intercept lock across that join (a concurrent disable would otherwise stall).
    let dead_engine = state.intercept_engine.lock().take();
    let Some(dead_engine) = dead_engine else {
        tracing::info!("Intercept recovery skipped: engine already cleared");
        return;
    };
    drop(dead_engine);

    tracing::warn!("Intercept loop failed open; restoring SNIFF monitoring");

    {
        let mut sniff_guard = state.sniff_engine.lock();
        if sniff_guard.is_none() {
            match CaptureEngine::start_sniff(
                Arc::clone(&state.process_mapper),
                Arc::clone(&state.traffic_tracker),
            ) {
                Ok(engine) => {
                    *sniff_guard = Some(engine);
                    tracing::info!("SNIFF mode restarted after intercept fail-open");
                }
                Err(e) => tracing::warn!("Failed to restart SNIFF after fail-open: {e:#}"),
            }
        }
    }

    if let Err(e) = app.emit(INTERCEPT_FAILED_OPEN_EVENT, ()) {
        tracing::warn!("Failed to emit intercept-failed-open event: {e}");
    }
}

#[tauri::command]
pub fn disable_intercept_mode(state: State<'_, AppState>) -> Result<(), AppError> {
    {
        let mut intercept_guard = state.intercept_engine.lock();
        if intercept_guard.take().is_some() {
            tracing::info!("INTERCEPT engine stopped");
        }
    }

    match CaptureEngine::start_sniff(
        Arc::clone(&state.process_mapper),
        Arc::clone(&state.traffic_tracker),
    ) {
        Ok(engine) => {
            *state.sniff_engine.lock() = Some(engine);
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
    Ok(state.intercept_engine.lock().is_some())
}
