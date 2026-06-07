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
    Block {
        pid: u32,
    },
    Limit {
        pid: u32,
        download_bps: u64,
        upload_bps: u64,
    },
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
        return Err(AppError::InvalidInput(
            "Intercept mode is already active".into(),
        ));
    }
    Ok(())
}

/// Maximum allowed length for a WinDivert filter string.
const MAX_FILTER_LEN: usize = 512;

/// Validate a WinDivert filter string for safety.
/// Rejects empty, overly long, non-ASCII, or null-byte-containing filters.
/// Also restricts to the character set used by WinDivert filter syntax.
///
/// Note: Full grammar validation is performed by `WinDivert::network()` at
/// handle creation time (`WinDivertOpenError::InvalidParameter`). This
/// pre-validation is a defense-in-depth layer against injection-class inputs.
pub fn validate_windivert_filter(filter: &str) -> Result<(), AppError> {
    if filter.trim().is_empty() {
        return Err(AppError::InvalidInput("Filter cannot be empty".into()));
    }
    if filter.len() > MAX_FILTER_LEN {
        return Err(AppError::InvalidInput(format!(
            "Filter too long ({} chars, max {MAX_FILTER_LEN})",
            filter.len()
        )));
    }
    if filter.bytes().any(|b| b == 0) {
        return Err(AppError::InvalidInput("Filter contains null bytes".into()));
    }
    if !filter.is_ascii() {
        return Err(AppError::InvalidInput(
            "Filter must contain only ASCII characters".into(),
        ));
    }
    // Restrict to characters valid in WinDivert filter syntax:
    // letters, digits, whitespace, comparison (=!<>), logical (&|?), grouping (()),
    // field access (.), colon (IPv6), comma, negation/subtraction (-).
    if !filter
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b" .,:!=<>()&|?-".contains(&b))
    {
        return Err(AppError::InvalidInput(
            "Filter contains characters not allowed in WinDivert filter syntax".into(),
        ));
    }
    Ok(())
}

/// Resolve and validate the WinDivert filter for intercept mode.
///
/// Defaults to [`crate::config::DEFAULT_CAPTURE_FILTER`] so that local IPC traffic
/// (DB connections, Tauri webview socket, local dev servers on 127.0.0.1/::1)
/// is excluded from throttling. Parens are required — WinDivert grammar binds
/// `and` tighter than `or`, so without them the filter would parse as
/// `tcp or (udp and not loopback)`, leaving loopback TCP un-excluded.
///
/// Custom filters (Some(...)) are passed through unchanged; developers may
/// explicitly capture loopback when needed (e.g. iperf3 on localhost).
///
/// NOTE: the default filter excludes loopback, so iperf3 tests on 127.0.0.1
/// will not be captured by default. Use a custom filter or a remote endpoint.
pub fn resolve_intercept_filter(filter: Option<String>) -> Result<String, AppError> {
    let filter = filter.unwrap_or_else(|| crate::config::DEFAULT_CAPTURE_FILTER.to_string());
    validate_windivert_filter(&filter)?;
    Ok(filter)
}

/// Validate that a PID is safe to request an icon for.
///
/// Rejects PIDs that would pass an arbitrary path to Win32 `ExtractIconExW`
/// via a privileged backend process (PID 0, 4, and NetGuard's own PID).
/// Delegates to `validate_control_pid` — same reserved-PID semantics apply.
pub fn validate_icon_request_pid(pid: u32) -> Result<(), AppError> {
    validate_control_pid(pid, std::process::id())
}

/// Validate an exe path that came from our own ProcessMapper before passing it
/// to Win32 `ExtractIconExW`.
///
/// Even though the path originates from our mapper (not the renderer), defense-
/// in-depth rejects:
/// - Empty paths
/// - Paths containing NUL bytes (would truncate the Win32 wide-string)
/// - UNC paths beginning with `\\` (unnecessary network I/O in the icon path)
///
/// The `\\` rejection also catches `\\?\` extended-length local paths; that is
/// fine because sysinfo resolves exe paths via `GetModuleFileNameExW`, which
/// never produces the extended-length prefix. Revisit if the process-info
/// source changes.
///
/// A bad path is treated as "no icon available" by the caller rather than an
/// error, because the caller owns the data quality — see `get_process_icon`.
pub fn validate_icon_exe_path(path: &str) -> Result<(), AppError> {
    if path.is_empty() {
        return Err(AppError::InvalidInput("Icon exe path is empty".into()));
    }
    if path.contains('\0') {
        return Err(AppError::InvalidInput(
            "Icon exe path contains null byte".into(),
        ));
    }
    if path.starts_with(r"\\") {
        return Err(AppError::InvalidInput(
            "UNC paths are not permitted for icon extraction".into(),
        ));
    }
    Ok(())
}

/// Validate that a PID is safe to control (set limits / block / unblock).
///
/// Rejects:
/// - PID 0 (Idle process — kernel sentinel)
/// - PID 4 (System — owns SMB/system networking; blocking it kills host networking)
/// - The current process's own PID (prevents self-throttling)
pub fn validate_control_pid(pid: u32, current_pid: u32) -> Result<(), AppError> {
    if pid == 0 || pid == 4 {
        return Err(AppError::InvalidInput(
            "Cannot control reserved system PID".into(),
        ));
    }
    if pid == current_pid {
        return Err(AppError::InvalidInput(
            "Cannot control NetGuard's own PID".into(),
        ));
    }
    Ok(())
}

/// Format the registry REG_SZ value for the Windows autostart Run key.
///
/// Windows resolves the value as a CreateProcess command line, so an unquoted
/// path like `C:\Program Files\app.exe` is parsed as `C:\Program` with argument
/// `Files\app.exe` — the classic unquoted-path vulnerability.  Wrapping in
/// double-quotes makes the entire path a single token regardless of spaces.
///
/// Note: `"` is an illegal character in Windows file/directory names, so the
/// replace here is pure defense-in-depth and will never trigger in practice.
pub fn format_run_value(exe_path: &str) -> String {
    // Escape any embedded quotes first (defense-in-depth; Windows filenames
    // cannot legally contain `"`, so this branch is unreachable in practice).
    format!("\"{}\"", exe_path.replace('"', "\\\""))
}

/// Validate that timestamp parameters are non-negative and properly ordered.
pub fn validate_timestamps(from: i64, to: i64) -> Result<(), AppError> {
    if from < 0 || to < 0 {
        return Err(AppError::InvalidInput(
            "Timestamps must be non-negative".into(),
        ));
    }
    if from > to {
        return Err(AppError::InvalidInput(
            "from_timestamp must be <= to_timestamp".into(),
        ));
    }
    Ok(())
}

/// Maximum allowed length for a profile name.
const MAX_PROFILE_NAME_LEN: usize = 64;

/// Validate a profile name. Allows ASCII alphanumeric, hyphens, underscores, spaces.
/// Returns the trimmed name on success for consistent storage.
pub fn validate_profile_name(name: &str) -> Result<String, AppError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AppError::InvalidInput(
            "Profile name cannot be empty".into(),
        ));
    }
    if trimmed.len() > MAX_PROFILE_NAME_LEN {
        return Err(AppError::InvalidInput(format!(
            "Profile name too long ({} chars, max {MAX_PROFILE_NAME_LEN})",
            trimmed.len()
        )));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ')
    {
        return Err(AppError::InvalidInput(
            "Profile name may only contain letters, digits, hyphens, underscores, and spaces"
                .into(),
        ));
    }
    Ok(trimmed.to_string())
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
        limits.insert(
            1,
            BandwidthLimit {
                download_bps: 1000,
                upload_bps: 500,
            },
        );
        let blocked = vec![2];
        let snapshot = vec![
            make_snapshot(1, "chrome.exe", r"C:\chrome.exe"),
            make_snapshot(2, "firefox.exe", r"C:\firefox.exe"),
        ];

        let rules = build_profile_rules(&limits, &blocked, &snapshot);
        assert_eq!(rules.len(), 2);

        let chrome_rule = rules
            .iter()
            .find(|r| r.exe_path == r"C:\chrome.exe")
            .unwrap();
        assert_eq!(chrome_rule.download_bps, 1000);
        assert!(!chrome_rule.blocked);

        let firefox_rule = rules
            .iter()
            .find(|r| r.exe_path == r"C:\firefox.exe")
            .unwrap();
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
        limits.insert(
            999,
            BandwidthLimit {
                download_bps: 1000,
                upload_bps: 500,
            },
        );
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
        assert_eq!(
            actions,
            vec![ApplyAction::Limit {
                pid: 10,
                download_bps: 1000,
                upload_bps: 500
            }]
        );
    }

    #[test]
    fn test_match_rules_empty_rules() {
        let snapshot = vec![make_snapshot(1, "chrome.exe", r"C:\chrome.exe")];
        assert!(match_rules_to_processes(&[], &snapshot).is_empty());
    }

    #[test]
    fn test_match_rules_no_matching_processes() {
        let rules = vec![make_rule(
            r"C:\notepad.exe",
            "notepad.exe",
            1000,
            500,
            false,
        )];
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
    fn test_validate_control_pid_rejects_reserved_pids() {
        assert!(validate_control_pid(0, 999).is_err());
        assert!(validate_control_pid(4, 999).is_err());
    }

    #[test]
    fn test_validate_control_pid_rejects_current_process() {
        assert!(validate_control_pid(999, 999).is_err());
    }

    #[test]
    fn test_validate_control_pid_accepts_user_pid() {
        assert!(validate_control_pid(1234, 999).is_ok());
    }

    // --- validate_icon_request_pid ---

    #[test]
    fn test_validate_icon_request_pid_rejects_reserved() {
        // PID 0 and 4 are always reserved on Windows.
        assert!(validate_icon_request_pid(0).is_err());
        assert!(validate_icon_request_pid(4).is_err());
    }

    #[test]
    fn test_validate_icon_request_pid_rejects_own_pid() {
        // NetGuard's own PID must be rejected.
        assert!(validate_icon_request_pid(std::process::id()).is_err());
    }

    #[test]
    fn test_validate_icon_request_pid_accepts_normal_pid() {
        // A PID that is not 0, 4, or the current process must be accepted.
        // Find a PID that differs from the current process and reserved PIDs.
        let candidate = if std::process::id() != 1000 {
            1000
        } else {
            1001
        };
        assert!(validate_icon_request_pid(candidate).is_ok());
    }

    // --- validate_icon_exe_path ---

    #[test]
    fn test_validate_icon_exe_path_rejects_empty() {
        assert!(validate_icon_exe_path("").is_err());
    }

    #[test]
    fn test_validate_icon_exe_path_rejects_nul_byte() {
        assert!(validate_icon_exe_path("C:\\x\0y.exe").is_err());
    }

    #[test]
    fn test_validate_icon_exe_path_rejects_unc() {
        assert!(validate_icon_exe_path(r"\\server\share\x.exe").is_err());
    }

    #[test]
    fn test_validate_icon_exe_path_accepts_normal_path() {
        assert!(validate_icon_exe_path(r"C:\Windows\notepad.exe").is_ok());
    }

    #[test]
    fn test_validate_intercept_enable_ok() {
        assert!(validate_intercept_enable(false).is_ok());
    }

    #[test]
    fn test_validate_intercept_enable_already_active() {
        assert_eq!(
            validate_intercept_enable(true).unwrap_err().kind(),
            "InvalidInput"
        );
    }

    #[test]
    fn test_resolve_filter_default() {
        // Loopback is excluded by default so local IPC (DB connections, Tauri
        // webview socket, dev servers) is neither counted nor throttled.
        // Parens are required: without them WinDivert grammar binds `and` tighter
        // than `or`, giving `tcp or (udp and not loopback)` — incorrect.
        assert_eq!(
            resolve_intercept_filter(None).unwrap(),
            "(tcp or udp) and not loopback"
        );
    }

    #[test]
    fn test_resolve_filter_default_passes_validation() {
        // The new default must pass validate_windivert_filter: it contains only
        // ASCII alphanumerics, spaces, and parentheses — all in the allowed set.
        let filter = resolve_intercept_filter(None).unwrap();
        assert!(
            validate_windivert_filter(&filter).is_ok(),
            "default intercept filter must pass validation: {filter}"
        );
    }

    #[test]
    fn test_resolve_filter_custom() {
        assert_eq!(
            resolve_intercept_filter(Some("tcp.DstPort == 5201".to_string())).unwrap(),
            "tcp.DstPort == 5201"
        );
    }

    #[test]
    fn test_validate_filter_rejects_empty() {
        let result = validate_windivert_filter("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_filter_rejects_too_long() {
        let long = "a".repeat(513);
        let result = validate_windivert_filter(&long);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_filter_rejects_null_bytes() {
        let result = validate_windivert_filter("tcp\0or udp");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_filter_rejects_non_ascii() {
        let result = validate_windivert_filter("tcp or удп");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_filter_rejects_whitespace_only() {
        assert!(validate_windivert_filter("   ").is_err());
        assert!(validate_windivert_filter(" ").is_err());
    }

    #[test]
    fn test_validate_filter_rejects_disallowed_chars() {
        assert!(validate_windivert_filter("tcp; drop table").is_err());
        assert!(validate_windivert_filter("tcp\nor udp").is_err());
        assert!(validate_windivert_filter("tcp `echo`").is_err());
        assert!(validate_windivert_filter("tcp $ udp").is_err());
    }

    #[test]
    fn test_validate_filter_accepts_valid() {
        assert!(validate_windivert_filter("tcp or udp").is_ok());
        assert!(validate_windivert_filter("tcp.DstPort == 5201").is_ok());
        assert!(validate_windivert_filter("tcp.DstPort == 5201 or tcp.SrcPort == 5201").is_ok());
        assert!(validate_windivert_filter("(tcp.DstPort == 80 or tcp.DstPort == 443)").is_ok());
        assert!(validate_windivert_filter("ip.SrcAddr == 192.168.1.1").is_ok());
        // WinDivert logical/bitwise operators
        assert!(validate_windivert_filter("tcp.DstPort == 80 && tcp.SrcPort > 1024").is_ok());
        assert!(validate_windivert_filter("tcp || udp").is_ok());
        assert!(validate_windivert_filter("ip.TTL > -1").is_ok());
    }

    #[test]
    fn test_validate_profile_name_accepts_valid() {
        assert_eq!(validate_profile_name("my-profile").unwrap(), "my-profile");
        assert_eq!(validate_profile_name("Profile_1").unwrap(), "Profile_1");
        assert_eq!(validate_profile_name("work").unwrap(), "work");
    }

    #[test]
    fn test_validate_profile_name_trims_whitespace() {
        assert_eq!(validate_profile_name("  work  ").unwrap(), "work");
    }

    #[test]
    fn test_validate_profile_name_rejects_empty() {
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name("   ").is_err());
    }

    #[test]
    fn test_validate_profile_name_rejects_too_long() {
        let long = "a".repeat(65);
        assert!(validate_profile_name(&long).is_err());
    }

    #[test]
    fn test_validate_profile_name_rejects_special_chars() {
        assert!(validate_profile_name("profile<script>").is_err());
        assert!(validate_profile_name("../etc/passwd").is_err());
        assert!(validate_profile_name("name\0null").is_err());
    }

    #[test]
    fn test_validate_profile_name_rejects_unicode() {
        assert!(validate_profile_name("профиль").is_err());
        assert!(validate_profile_name("profile_αβγ").is_err());
    }

    // --- format_run_value ---

    #[test]
    fn test_format_run_value_quotes_paths_with_spaces() {
        assert_eq!(
            format_run_value(r"C:\Program Files\NetGuard\netguard.exe"),
            r#""C:\Program Files\NetGuard\netguard.exe""#
        );
    }

    #[test]
    fn test_format_run_value_quotes_paths_without_spaces() {
        // Always quote — simplest and safe even for paths without spaces.
        assert_eq!(
            format_run_value(r"C:\NetGuard\netguard.exe"),
            r#""C:\NetGuard\netguard.exe""#
        );
    }

    #[test]
    fn test_format_run_value_escapes_embedded_quote() {
        // Defense-in-depth: embedded quotes (illegal in Windows paths) are escaped.
        assert_eq!(
            format_run_value(r#"C:\bad"path\app.exe"#),
            r#""C:\bad\"path\app.exe""#
        );
    }

    #[test]
    fn test_validate_timestamps_accepts_valid() {
        assert!(validate_timestamps(0, 100).is_ok());
        assert!(validate_timestamps(100, 100).is_ok());
        assert!(validate_timestamps(0, 0).is_ok());
    }

    #[test]
    fn test_validate_timestamps_rejects_negative() {
        assert!(validate_timestamps(-1, 100).is_err());
        assert!(validate_timestamps(0, -1).is_err());
        assert!(validate_timestamps(-5, -1).is_err());
    }

    #[test]
    fn test_validate_timestamps_rejects_inverted_range() {
        assert!(validate_timestamps(200, 100).is_err());
    }
}
