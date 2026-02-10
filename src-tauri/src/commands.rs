/// Tauri IPC command handlers.
/// All #[tauri::command] functions go here and are registered in lib.rs.
use std::collections::HashMap;
use std::sync::Arc;

use tauri::State;

use crate::capture::CaptureEngine;
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
    /// Bandwidth threshold for notifications (bytes/sec, 0 = disabled). (AC-6.4)
    pub notification_threshold_bps: Arc<std::sync::atomic::AtomicU64>,
    /// Persistent rules from the active profile, auto-applied to new processes. (F7)
    pub persistent_rules: Arc<std::sync::Mutex<Vec<db::SavedRule>>>,
    /// Active SNIFF engine (stopped when intercept is active to avoid double-counting).
    pub sniff_engine: std::sync::Mutex<Option<CaptureEngine>>,
    /// Active intercept engine (None when in SNIFF-only mode). (Phase 2)
    pub intercept_engine: std::sync::Mutex<Option<CaptureEngine>>,
}

// ---- F1: Traffic Monitoring ----

/// Returns the current traffic snapshot for all monitored processes.
#[tauri::command]
pub fn get_traffic_stats(state: State<'_, AppState>) -> Vec<ProcessTrafficSnapshot> {
    state.traffic_tracker.snapshot(&state.process_mapper)
}

// ---- AC-1.6: Process Icons ----

/// Get the base64-encoded icon data URI for a process executable.
/// Returns None if the icon cannot be extracted or the path is empty.
#[tauri::command]
pub fn get_process_icon(state: State<'_, AppState>, exe_path: String) -> Option<String> {
    state.process_mapper.get_icon_base64(&exe_path)
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
    tracing::info!("Set bandwidth limit for PID {pid}: DL={download_bps} B/s, UL={upload_bps} B/s");
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

// ---- F5: Rule Profiles ----

/// Save the current bandwidth limits and blocks as a named profile.
#[tauri::command]
pub fn save_profile(state: State<'_, AppState>, profile_name: String) -> Result<(), String> {
    let limits = state.rate_limiter.get_all_limits();
    let blocked_pids = state.rate_limiter.get_blocked_pids();
    let snapshot = state.traffic_tracker.snapshot(&state.process_mapper);

    // Build PID → process info map for exe_path lookup.
    let pid_to_info: std::collections::HashMap<u32, &ProcessTrafficSnapshot> =
        snapshot.iter().map(|s| (s.pid, s)).collect();

    // Save each bandwidth limit as a rule.
    for (pid, limit) in &limits {
        if let Some(info) = pid_to_info.get(pid) {
            state
                .database
                .save_rule(
                    &profile_name,
                    &info.exe_path,
                    &info.name,
                    limit.download_bps,
                    limit.upload_bps,
                    false,
                )
                .map_err(|e| e.to_string())?;
        }
    }

    // Save blocked processes as rules.
    for pid in &blocked_pids {
        if let Some(info) = pid_to_info.get(pid) {
            state
                .database
                .save_rule(&profile_name, &info.exe_path, &info.name, 0, 0, true)
                .map_err(|e| e.to_string())?;
        }
    }

    tracing::info!(
        "Saved profile '{profile_name}' with {} rules",
        limits.len() + blocked_pids.len()
    );
    Ok(())
}

/// Apply a saved profile: clear current rules and apply all rules from the profile.
/// Also stores rules as persistent rules for auto-application to new processes (F7).
/// Returns the number of rules applied to currently running processes.
#[tauri::command]
pub fn apply_profile(state: State<'_, AppState>, profile_name: String) -> Result<usize, String> {
    let rules = state
        .database
        .load_rules(&profile_name)
        .map_err(|e| e.to_string())?;

    // Clear current limits and blocks.
    state.rate_limiter.clear_all();

    // Store as persistent rules for auto-application (AC-7.2, AC-7.3).
    *state.persistent_rules.lock().unwrap() = rules.clone();

    // Get current running processes to match rules by exe_path.
    let snapshot = state.traffic_tracker.snapshot(&state.process_mapper);

    let mut applied = 0;
    for rule in &rules {
        for proc in &snapshot {
            if proc.exe_path == rule.exe_path {
                if rule.blocked {
                    state.rate_limiter.block_process(proc.pid);
                } else if rule.download_bps > 0 || rule.upload_bps > 0 {
                    state.rate_limiter.set_limit(
                        proc.pid,
                        BandwidthLimit {
                            download_bps: rule.download_bps,
                            upload_bps: rule.upload_bps,
                        },
                    );
                }
                applied += 1;
            }
        }
    }

    tracing::info!(
        "Applied profile '{profile_name}': {applied}/{} rules matched running processes",
        rules.len()
    );
    Ok(applied)
}

/// List all saved profile names.
#[tauri::command]
pub fn list_profiles(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    state.database.list_profiles().map_err(|e| e.to_string())
}

/// Delete a saved profile.
#[tauri::command]
pub fn delete_profile(state: State<'_, AppState>, profile_name: String) -> Result<(), String> {
    state
        .database
        .delete_profile(&profile_name)
        .map_err(|e| e.to_string())?;
    tracing::info!("Deleted profile '{profile_name}'");
    Ok(())
}

/// Get rules for a specific profile.
#[tauri::command]
pub fn get_profile_rules(
    state: State<'_, AppState>,
    profile_name: String,
) -> Result<Vec<db::SavedRule>, String> {
    state
        .database
        .load_rules(&profile_name)
        .map_err(|e| e.to_string())
}

// ---- AC-6.4: Bandwidth Threshold Notifications ----

/// Set the bandwidth notification threshold (bytes/sec). 0 disables notifications.
#[tauri::command]
pub fn set_notification_threshold(state: State<'_, AppState>, threshold_bps: u64) {
    state
        .notification_threshold_bps
        .store(threshold_bps, std::sync::atomic::Ordering::Relaxed);
    tracing::info!("Notification threshold set to {threshold_bps} B/s");
}

/// Get the current notification threshold.
#[tauri::command]
pub fn get_notification_threshold(state: State<'_, AppState>) -> u64 {
    state
        .notification_threshold_bps
        .load(std::sync::atomic::Ordering::Relaxed)
}

// ---- F7: Auto-Start ----

/// Enable or disable auto-start on login.
#[tauri::command]
pub fn set_autostart(enabled: bool) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe_str = exe.to_string_lossy().to_string();

        // Use Windows Registry via reg.exe for simplicity.
        let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        if enabled {
            let output = std::process::Command::new("reg")
                .args([
                    "add", key, "/v", "NetGuard", "/t", "REG_SZ", "/d", &exe_str, "/f",
                ])
                .output()
                .map_err(|e| e.to_string())?;
            if !output.status.success() {
                return Err("Failed to add registry entry".into());
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

    #[cfg(target_os = "macos")]
    {
        // macOS: write/remove a LaunchAgent plist.
        let home = std::env::var("HOME").map_err(|e| e.to_string())?;
        let plist_path = PathBuf::from(&home).join("Library/LaunchAgents/com.netguard.app.plist");
        if enabled {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.netguard.app</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"#,
                exe.to_string_lossy()
            );
            std::fs::write(&plist_path, plist).map_err(|e| e.to_string())?;
            tracing::info!("Auto-start enabled (LaunchAgent)");
        } else {
            let _ = std::fs::remove_file(&plist_path);
            tracing::info!("Auto-start disabled");
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    Err("Auto-start not supported on this platform".into())
}

/// Check if auto-start is currently enabled.
#[tauri::command]
pub fn get_autostart() -> bool {
    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("reg")
            .args([
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "NetGuard",
            ])
            .output();
        matches!(output, Ok(o) if o.status.success())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        std::path::Path::new(&home)
            .join("Library/LaunchAgents/com.netguard.app.plist")
            .exists()
    }
}

// ---- Phase 2: Intercept Mode Activation ----

/// Enable intercept mode with the given WinDivert/pf filter.
/// This allows rate limiting and blocking to actually affect network traffic.
///
/// Stops the SNIFF engine first to avoid double-counting traffic (both loops
/// call `record_bytes` on the same `TrafficTracker`).
///
/// SAFETY: Use a narrow filter during development (PRD S2).
#[tauri::command]
pub fn enable_intercept_mode(
    state: State<'_, AppState>,
    filter: Option<String>,
) -> Result<(), String> {
    let mut intercept_guard = state.intercept_engine.lock().unwrap();
    if intercept_guard.is_some() {
        return Err("Intercept mode is already active".into());
    }

    // Stop SNIFF engine to prevent double-counting.
    // Drop triggers WinDivertShutdown + thread join.
    {
        let mut sniff_guard = state.sniff_engine.lock().unwrap();
        if sniff_guard.take().is_some() {
            tracing::info!("SNIFF engine stopped (switching to intercept)");
        }
    }

    let filter = filter.unwrap_or_else(|| "tcp or udp".to_string());
    tracing::info!("Enabling INTERCEPT mode with filter: {filter}");

    let engine = CaptureEngine::start_intercept(
        Arc::clone(&state.process_mapper),
        Arc::clone(&state.traffic_tracker),
        Arc::clone(&state.rate_limiter),
        filter,
    )
    .map_err(|e| e.to_string())?;

    *intercept_guard = Some(engine);
    Ok(())
}

/// Disable intercept mode, returning to SNIFF-only monitoring.
///
/// Drops the intercept engine (triggers WinDivertShutdown to unblock recv,
/// then joins the capture thread) and restarts the SNIFF engine.
#[tauri::command]
pub fn disable_intercept_mode(state: State<'_, AppState>) -> Result<(), String> {
    // Stop intercept engine. Drop triggers clean shutdown + thread join.
    {
        let mut intercept_guard = state.intercept_engine.lock().unwrap();
        if intercept_guard.take().is_some() {
            tracing::info!("INTERCEPT engine stopped");
        }
    }

    // Restart SNIFF engine for monitoring.
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

/// Check if intercept mode is currently active.
#[tauri::command]
pub fn is_intercept_active(state: State<'_, AppState>) -> bool {
    state.intercept_engine.lock().unwrap().is_some()
}
