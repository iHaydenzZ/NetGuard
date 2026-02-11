/// Tauri IPC command handlers.
/// All #[tauri::command] functions go here and are registered in lib.rs.
///
/// Business logic is extracted into pure functions (prefixed with no `#[tauri::command]`)
/// so they can be unit-tested without a Tauri runtime.
use std::collections::HashMap;
use std::sync::Arc;

use tauri::State;

use crate::capture::CaptureEngine;
use crate::core::process_mapper::ProcessMapper;
use crate::core::rate_limiter::{BandwidthLimit, RateLimiterManager};
use crate::core::traffic::{ProcessTrafficSnapshot, TrafficTracker};
use crate::db::{self, Database, TrafficSummary};
use crate::error::AppError;

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

// ===========================================================================
// Pure business logic functions (no Tauri State dependency, unit-testable)
// ===========================================================================

/// A rule entry to be persisted to the database.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleEntry {
    pub exe_path: String,
    pub process_name: String,
    pub download_bps: u64,
    pub upload_bps: u64,
    pub blocked: bool,
}

/// An action to be applied to a running process when activating a profile.
#[derive(Debug, Clone, PartialEq)]
pub enum ApplyAction {
    Block { pid: u32 },
    Limit { pid: u32, download_bps: u64, upload_bps: u64 },
}

/// Build the list of rules to save from the current limits, blocks, and process snapshot.
///
/// For each limited or blocked PID that exists in the snapshot, produces a `RuleEntry`
/// keyed by `exe_path` so the rule can be re-applied to future process instances.
pub fn build_profile_rules(
    limits: &HashMap<u32, BandwidthLimit>,
    blocked_pids: &[u32],
    snapshot: &[ProcessTrafficSnapshot],
) -> Vec<RuleEntry> {
    let pid_to_info: HashMap<u32, &ProcessTrafficSnapshot> =
        snapshot.iter().map(|s| (s.pid, s)).collect();

    let mut rules = Vec::new();

    for (pid, limit) in limits {
        if let Some(info) = pid_to_info.get(pid) {
            rules.push(RuleEntry {
                exe_path: info.exe_path.clone(),
                process_name: info.name.clone(),
                download_bps: limit.download_bps,
                upload_bps: limit.upload_bps,
                blocked: false,
            });
        }
    }

    for pid in blocked_pids {
        if let Some(info) = pid_to_info.get(pid) {
            rules.push(RuleEntry {
                exe_path: info.exe_path.clone(),
                process_name: info.name.clone(),
                download_bps: 0,
                upload_bps: 0,
                blocked: true,
            });
        }
    }

    rules
}

/// Match saved rules against running processes and produce a list of actions.
///
/// Returns the actions to apply and the count of matched rules.
pub fn match_rules_to_processes(
    rules: &[db::SavedRule],
    snapshot: &[ProcessTrafficSnapshot],
) -> Vec<ApplyAction> {
    let mut actions = Vec::new();

    for rule in rules {
        for proc in snapshot {
            if proc.exe_path == rule.exe_path {
                if rule.blocked {
                    actions.push(ApplyAction::Block { pid: proc.pid });
                } else if rule.download_bps > 0 || rule.upload_bps > 0 {
                    actions.push(ApplyAction::Limit {
                        pid: proc.pid,
                        download_bps: rule.download_bps,
                        upload_bps: rule.upload_bps,
                    });
                }
            }
        }
    }

    actions
}

/// Validate that intercept mode can be enabled (not already active).
pub fn validate_intercept_enable(is_active: bool) -> Result<(), AppError> {
    if is_active {
        return Err(AppError::InvalidInput(
            "Intercept mode is already active".into(),
        ));
    }
    Ok(())
}

/// Resolve the WinDivert filter, defaulting to "tcp or udp" if not specified.
pub fn resolve_intercept_filter(filter: Option<String>) -> String {
    filter.unwrap_or_else(|| "tcp or udp".to_string())
}

// ===========================================================================
// Tauri command handlers (thin delegation layer)
// ===========================================================================

// ---- F1: Traffic Monitoring ----

#[tauri::command]
pub fn get_traffic_stats(
    state: State<'_, AppState>,
) -> Result<Vec<ProcessTrafficSnapshot>, AppError> {
    Ok(state.traffic_tracker.snapshot(&state.process_mapper))
}

// ---- AC-1.6: Process Icons ----

#[tauri::command]
pub fn get_process_icon(
    state: State<'_, AppState>,
    exe_path: String,
) -> Result<Option<String>, AppError> {
    Ok(state.process_mapper.get_icon_base64(&exe_path))
}

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
pub fn remove_bandwidth_limit(
    state: State<'_, AppState>,
    pid: u32,
) -> Result<(), AppError> {
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

// ---- F4: Traffic History ----

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
pub fn delete_profile(
    state: State<'_, AppState>,
    profile_name: String,
) -> Result<(), AppError> {
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
    state
        .database
        .load_rules(&profile_name)
        .map_err(|e| AppError::Database(e.to_string()))
}

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
            .args(["add", key, "/v", "NetGuard", "/t", "REG_SZ", "/d", &exe_str, "/f"])
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
        .args(["query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "NetGuard"])
        .output();
    Ok(matches!(output, Ok(o) if o.status.success()))
}

// ---- Phase 2: Intercept Mode Activation ----

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

// ===========================================================================
// Unit tests for pure business logic functions
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_snapshot(pid: u32, name: &str, exe_path: &str) -> ProcessTrafficSnapshot {
        ProcessTrafficSnapshot {
            pid,
            name: name.to_string(),
            exe_path: exe_path.to_string(),
            upload_speed: 0.0,
            download_speed: 0.0,
            bytes_sent: 0,
            bytes_recv: 0,
            connection_count: 0,
        }
    }

    fn make_rule(exe_path: &str, name: &str, dl: u64, ul: u64, blocked: bool) -> db::SavedRule {
        db::SavedRule {
            exe_path: exe_path.to_string(),
            process_name: name.to_string(),
            download_bps: dl,
            upload_bps: ul,
            blocked,
        }
    }

    // ---- build_profile_rules tests ----

    #[test]
    fn test_build_profile_rules_with_limits_and_blocks() {
        let mut limits = HashMap::new();
        limits.insert(1, BandwidthLimit { download_bps: 1000, upload_bps: 500 });
        let blocked = vec![2];
        let snapshot = vec![
            make_snapshot(1, "chrome.exe", r"C:\chrome.exe"),
            make_snapshot(2, "firefox.exe", r"C:\firefox.exe"),
        ];

        let rules = build_profile_rules(&limits, &blocked, &snapshot);
        assert_eq!(rules.len(), 2);

        let chrome_rule = rules.iter().find(|r| r.exe_path == r"C:\chrome.exe").unwrap();
        assert_eq!(chrome_rule.download_bps, 1000);
        assert_eq!(chrome_rule.upload_bps, 500);
        assert!(!chrome_rule.blocked);

        let firefox_rule = rules.iter().find(|r| r.exe_path == r"C:\firefox.exe").unwrap();
        assert!(firefox_rule.blocked);
        assert_eq!(firefox_rule.download_bps, 0);
    }

    #[test]
    fn test_build_profile_rules_empty_inputs() {
        let rules = build_profile_rules(&HashMap::new(), &[], &[]);
        assert!(rules.is_empty());
    }

    #[test]
    fn test_build_profile_rules_pid_not_in_snapshot() {
        let mut limits = HashMap::new();
        limits.insert(999, BandwidthLimit { download_bps: 1000, upload_bps: 500 });
        let snapshot = vec![make_snapshot(1, "chrome.exe", r"C:\chrome.exe")];

        let rules = build_profile_rules(&limits, &[], &snapshot);
        assert!(rules.is_empty(), "PID not in snapshot should be skipped");
    }

    #[test]
    fn test_build_profile_rules_blocked_pid_not_in_snapshot() {
        let blocked = vec![999];
        let snapshot = vec![make_snapshot(1, "chrome.exe", r"C:\chrome.exe")];

        let rules = build_profile_rules(&HashMap::new(), &blocked, &snapshot);
        assert!(rules.is_empty());
    }

    // ---- match_rules_to_processes tests ----

    #[test]
    fn test_match_rules_block_action() {
        let rules = vec![make_rule(r"C:\firefox.exe", "firefox.exe", 0, 0, true)];
        let snapshot = vec![make_snapshot(42, "firefox.exe", r"C:\firefox.exe")];

        let actions = match_rules_to_processes(&rules, &snapshot);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], ApplyAction::Block { pid: 42 });
    }

    #[test]
    fn test_match_rules_limit_action() {
        let rules = vec![make_rule(r"C:\chrome.exe", "chrome.exe", 1000, 500, false)];
        let snapshot = vec![make_snapshot(10, "chrome.exe", r"C:\chrome.exe")];

        let actions = match_rules_to_processes(&rules, &snapshot);
        assert_eq!(actions.len(), 1);
        assert_eq!(
            actions[0],
            ApplyAction::Limit { pid: 10, download_bps: 1000, upload_bps: 500 }
        );
    }

    #[test]
    fn test_match_rules_empty_rules() {
        let snapshot = vec![make_snapshot(1, "chrome.exe", r"C:\chrome.exe")];
        let actions = match_rules_to_processes(&[], &snapshot);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_match_rules_no_matching_processes() {
        let rules = vec![make_rule(r"C:\notepad.exe", "notepad.exe", 1000, 500, false)];
        let snapshot = vec![make_snapshot(1, "chrome.exe", r"C:\chrome.exe")];

        let actions = match_rules_to_processes(&rules, &snapshot);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_match_rules_zero_limits_skipped() {
        let rules = vec![make_rule(r"C:\chrome.exe", "chrome.exe", 0, 0, false)];
        let snapshot = vec![make_snapshot(1, "chrome.exe", r"C:\chrome.exe")];

        let actions = match_rules_to_processes(&rules, &snapshot);
        assert!(actions.is_empty(), "Rule with 0/0 limits and not blocked should produce no action");
    }

    #[test]
    fn test_match_rules_multiple_processes_same_exe() {
        let rules = vec![make_rule(r"C:\chrome.exe", "chrome.exe", 1000, 500, false)];
        let snapshot = vec![
            make_snapshot(1, "chrome.exe", r"C:\chrome.exe"),
            make_snapshot(2, "chrome.exe", r"C:\chrome.exe"),
        ];

        let actions = match_rules_to_processes(&rules, &snapshot);
        assert_eq!(actions.len(), 2, "Should match both PIDs with same exe_path");
    }

    // ---- validate_intercept_enable tests ----

    #[test]
    fn test_validate_intercept_enable_ok() {
        assert!(validate_intercept_enable(false).is_ok());
    }

    #[test]
    fn test_validate_intercept_enable_already_active() {
        let err = validate_intercept_enable(true).unwrap_err();
        assert_eq!(err.kind(), "InvalidInput");
    }

    // ---- resolve_intercept_filter tests ----

    #[test]
    fn test_resolve_filter_default() {
        assert_eq!(resolve_intercept_filter(None), "tcp or udp");
    }

    #[test]
    fn test_resolve_filter_custom() {
        let f = resolve_intercept_filter(Some("tcp.DstPort == 5201".to_string()));
        assert_eq!(f, "tcp.DstPort == 5201");
    }
}
