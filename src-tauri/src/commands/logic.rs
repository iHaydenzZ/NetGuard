//! Pure business logic functions extracted from Tauri command handlers.
//!
//! These functions take plain parameters (no Tauri State dependency) and
//! can be unit-tested without a Tauri runtime.

use std::collections::HashMap;

use crate::core::{BandwidthLimit, ProcessTrafficSnapshot};
use crate::db;
use crate::error::AppError;

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
        return Err(AppError::InvalidInput("Intercept mode is already active".into()));
    }
    Ok(())
}

/// Resolve the WinDivert filter, defaulting to "tcp or udp" if not specified.
pub fn resolve_intercept_filter(filter: Option<String>) -> String {
    filter.unwrap_or_else(|| "tcp or udp".to_string())
}

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
        assert!(!chrome_rule.blocked);

        let firefox_rule = rules.iter().find(|r| r.exe_path == r"C:\firefox.exe").unwrap();
        assert!(firefox_rule.blocked);
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
        assert!(rules.is_empty());
    }

    #[test]
    fn test_build_profile_rules_blocked_pid_not_in_snapshot() {
        let blocked = vec![999];
        let snapshot = vec![make_snapshot(1, "chrome.exe", r"C:\chrome.exe")];
        let rules = build_profile_rules(&HashMap::new(), &blocked, &snapshot);
        assert!(rules.is_empty());
    }

    #[test]
    fn test_match_rules_block_action() {
        let rules = vec![make_rule(r"C:\firefox.exe", "firefox.exe", 0, 0, true)];
        let snapshot = vec![make_snapshot(42, "firefox.exe", r"C:\firefox.exe")];
        let actions = match_rules_to_processes(&rules, &snapshot);
        assert_eq!(actions, vec![ApplyAction::Block { pid: 42 }]);
    }

    #[test]
    fn test_match_rules_limit_action() {
        let rules = vec![make_rule(r"C:\chrome.exe", "chrome.exe", 1000, 500, false)];
        let snapshot = vec![make_snapshot(10, "chrome.exe", r"C:\chrome.exe")];
        let actions = match_rules_to_processes(&rules, &snapshot);
        assert_eq!(actions, vec![ApplyAction::Limit { pid: 10, download_bps: 1000, upload_bps: 500 }]);
    }

    #[test]
    fn test_match_rules_empty_rules() {
        let snapshot = vec![make_snapshot(1, "chrome.exe", r"C:\chrome.exe")];
        assert!(match_rules_to_processes(&[], &snapshot).is_empty());
    }

    #[test]
    fn test_match_rules_no_matching_processes() {
        let rules = vec![make_rule(r"C:\notepad.exe", "notepad.exe", 1000, 500, false)];
        let snapshot = vec![make_snapshot(1, "chrome.exe", r"C:\chrome.exe")];
        assert!(match_rules_to_processes(&rules, &snapshot).is_empty());
    }

    #[test]
    fn test_match_rules_zero_limits_skipped() {
        let rules = vec![make_rule(r"C:\chrome.exe", "chrome.exe", 0, 0, false)];
        let snapshot = vec![make_snapshot(1, "chrome.exe", r"C:\chrome.exe")];
        assert!(match_rules_to_processes(&rules, &snapshot).is_empty());
    }

    #[test]
    fn test_match_rules_multiple_processes_same_exe() {
        let rules = vec![make_rule(r"C:\chrome.exe", "chrome.exe", 1000, 500, false)];
        let snapshot = vec![
            make_snapshot(1, "chrome.exe", r"C:\chrome.exe"),
            make_snapshot(2, "chrome.exe", r"C:\chrome.exe"),
        ];
        assert_eq!(match_rules_to_processes(&rules, &snapshot).len(), 2);
    }

    #[test]
    fn test_validate_intercept_enable_ok() {
        assert!(validate_intercept_enable(false).is_ok());
    }

    #[test]
    fn test_validate_intercept_enable_already_active() {
        assert_eq!(validate_intercept_enable(true).unwrap_err().kind(), "InvalidInput");
    }

    #[test]
    fn test_resolve_filter_default() {
        assert_eq!(resolve_intercept_filter(None), "tcp or udp");
    }

    #[test]
    fn test_resolve_filter_custom() {
        assert_eq!(
            resolve_intercept_filter(Some("tcp.DstPort == 5201".to_string())),
            "tcp.DstPort == 5201"
        );
    }
}
