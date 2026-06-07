//! Windows packet capture using WinDivert 2.x.
//!
//! Supports two modes:
//! - SNIFF: read-only packet copies for monitoring (Phase 1, zero risk)
//! - INTERCEPT: captures and re-injects packets for rate limiting (Phase 2+)
//!
//! Handle creation is separated from the capture loop so that the caller
//! (CaptureEngine) can extract the raw HANDLE for cross-thread shutdown.
//!
//! SAFETY: In intercept mode, packets are diverted from the network stack.
//! Always use the narrowest possible filter during development.
//! See PRD section 8.2 for mandatory safeguards.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use windivert::prelude::*;

use crate::capture::parse_ip_packet;
use crate::core::process_mapper::ProcessMapper;
use crate::core::rate_limiter::RateLimiterManager;
use crate::core::traffic::TrafficTracker;

/// Recv buffer size in intercept mode. Must cover WINDIVERT_MTU_MAX (65_575 for
/// WinDivert 2.2 bindings) so a maximum-size packet is never truncated; a
/// truncated re-injected packet would corrupt the connection.
const INTERCEPT_RECV_BUFFER_BYTES: usize = 65_575;

/// Recv buffer size in SNIFF mode. Read-only copies, but sized the same as the
/// intercept buffer for consistency and full-MTU coverage.
const SNIFF_RECV_BUFFER_BYTES: usize = 65_575;

/// What to do when `recv()` returns an error in intercept mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterceptRecvErrorAction {
    /// Expected shutdown signal (WinDivertShutdown called) — exit quietly.
    BreakCleanly,
    /// Unknown error — drop the divert handle so the OS resumes normal delivery
    /// (fail-open). Continuing with a live handle after an unknown error risks a
    /// wedged loop that freezes the host network.
    BreakFailOpen,
}

/// Classify an intercept-mode recv error into a fail-open or clean-shutdown action.
///
/// WinDivert raises `NoData` (Win32 error 232) when `WinDivertShutdown` is
/// called, which is our intentional stop path. Any other error is treated as
/// unexpected and fails open.
fn classify_intercept_recv_error(err: &str) -> InterceptRecvErrorAction {
    if err.contains("NoData") || err.contains("232") {
        InterceptRecvErrorAction::BreakCleanly
    } else {
        InterceptRecvErrorAction::BreakFailOpen
    }
}

/// Decide whether the app layer should run unexpected-exit recovery (drop dead
/// engine, restart SNIFF, notify frontend) after the intercept loop exits.
///
/// Only the fail-open path is an unexpected death. `BreakCleanly` is the
/// intentional-shutdown path (user disabled intercept / app exiting) and must
/// NOT trigger recovery — otherwise we'd double-restart SNIFF and emit a
/// misleading "intercept died" event.
fn intercept_exit_should_recover(action: InterceptRecvErrorAction) -> bool {
    matches!(action, InterceptRecvErrorAction::BreakFailOpen)
}

/// Create a WinDivert handle in SNIFF mode (read-only packet copies).
pub fn create_sniff_handle() -> Result<WinDivert<windivert::layer::NetworkLayer>> {
    let filter = "tcp or udp";
    let flags = WinDivertFlags::new().set_sniff();

    tracing::info!("Opening WinDivert SNIFF handle with filter: {filter}");
    WinDivert::network(filter, 0, flags).map_err(|e| {
        tracing::error!("WinDivert::network() SNIFF failed: {e:?}");
        anyhow::anyhow!(
            "Failed to open WinDivert SNIFF handle (filter={filter}): {e:?}. \
             Ensure WinDivert.dll and WinDivert64.sys are next to the executable \
             and the app is running as administrator."
        )
    })
}

/// Create a WinDivert handle in INTERCEPT mode (diverts packets from the stack).
pub fn create_intercept_handle(filter: &str) -> Result<WinDivert<windivert::layer::NetworkLayer>> {
    let flags = WinDivertFlags::new(); // default = intercept mode

    tracing::info!("Opening WinDivert INTERCEPT handle with filter: {filter}");
    WinDivert::network(filter, 0, flags)
        .context("Failed to open WinDivert handle for intercept mode")
}

/// Main SNIFF capture loop running in a dedicated OS thread.
/// Packets are copied, never intercepted — zero risk to network connectivity.
///
/// Accepts a pre-created WinDivert handle (created by `create_sniff_handle`).
pub fn run_sniff_loop(
    wd: WinDivert<windivert::layer::NetworkLayer>,
    process_mapper: Arc<ProcessMapper>,
    traffic_tracker: Arc<TrafficTracker>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    tracing::info!("WinDivert SNIFF capture loop started");

    let mut buf = vec![0u8; SNIFF_RECV_BUFFER_BYTES];

    while !shutdown.load(Ordering::Relaxed) {
        match wd.recv(Some(&mut buf)) {
            Ok(packet) => {
                let outbound = packet.address.outbound();
                process_sniff_packet(&process_mapper, &traffic_tracker, &packet.data, outbound);
            }
            Err(e) => {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                // NoData error means WinDivertShutdown was called — clean exit.
                let err_str = format!("{e}");
                if err_str.contains("NoData") || err_str.contains("232") {
                    tracing::info!("WinDivert SNIFF recv got shutdown signal");
                    break;
                }
                tracing::error!("WinDivert recv error: {e}");
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    tracing::info!("WinDivert SNIFF capture stopped");
    Ok(())
}

/// Intercept capture loop. Packets matching the filter are diverted from the
/// network stack, passed through the rate limiter, and re-injected.
///
/// Uses drop-based policing: packets exceeding the rate limit are dropped
/// rather than delayed, so the single-threaded loop never blocks. TCP
/// congestion control naturally reduces throughput when packets are dropped.
///
/// Accepts a pre-created WinDivert handle (created by `create_intercept_handle`).
///
/// `on_unexpected_exit` is invoked exactly once, on the capture thread, if and
/// only if the loop exits because of an unknown recv error (fail-open). It is
/// NOT called on intentional shutdown. The app layer uses it to drop the dead
/// engine, restart SNIFF monitoring, and notify the frontend. The callback must
/// not block on this thread's own join (see `commands/system.rs`).
///
/// SAFETY: Uses a narrow filter (specific port) during Phase 2a development.
/// See PRD S2 — never use "tcp or udp" in intercept mode during development.
pub fn run_intercept_loop(
    mut wd: WinDivert<windivert::layer::NetworkLayer>,
    process_mapper: Arc<ProcessMapper>,
    traffic_tracker: Arc<TrafficTracker>,
    rate_limiter: Arc<RateLimiterManager>,
    shutdown: Arc<AtomicBool>,
    on_unexpected_exit: Box<dyn FnOnce() + Send>,
) {
    tracing::info!("WinDivert INTERCEPT capture loop started");

    let mut buf = vec![0u8; INTERCEPT_RECV_BUFFER_BYTES];

    // Defaults to a clean exit; only an unknown recv error escalates to fail-open.
    let mut exit_action = InterceptRecvErrorAction::BreakCleanly;

    while !shutdown.load(Ordering::Relaxed) {
        match wd.recv(Some(&mut buf)) {
            Ok(packet) => {
                // If shutdown was requested while we were blocked on recv,
                // re-inject this packet and exit cleanly.
                if shutdown.load(Ordering::Relaxed) {
                    let _ = wd.send(&packet);
                    break;
                }

                let outbound = packet.address.outbound();

                // Account traffic (same as SNIFF mode).
                process_sniff_packet(&process_mapper, &traffic_tracker, &packet.data, outbound);

                // Decide: pass or drop.
                // Non-rate-limited / non-blocked packets pass immediately.
                // Blocked or over-budget packets are silently dropped.
                if should_pass_packet(&process_mapper, &rate_limiter, &packet.data, outbound) {
                    // Re-inject the packet back into the network stack.
                    if let Err(e) = wd.send(&packet) {
                        tracing::error!("WinDivert send error: {e}");
                    }
                }
                // else: packet dropped (blocked or rate exceeded)
            }
            Err(e) => {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                // Unlike SNIFF mode (read-only, tolerant of transient errors),
                // intercept mode holds a live divert handle: packets it receives
                // but does not re-inject are dropped. A wedged loop after an
                // unknown error = network freeze. So we never sleep-and-retry
                // here — we drop the handle to restore normal delivery.
                let err_str = format!("{e}");
                exit_action = classify_intercept_recv_error(&err_str);
                match exit_action {
                    InterceptRecvErrorAction::BreakCleanly => {
                        tracing::info!("WinDivert INTERCEPT recv got shutdown signal");
                    }
                    InterceptRecvErrorAction::BreakFailOpen => {
                        tracing::error!(
                            "WinDivert recv error in intercept mode; \
                             dropping handle to fail open: {e}"
                        );
                    }
                }
                break;
            }
        }
    }

    // Explicitly close the divert handle so the driver uninstalls the filter
    // and the OS resumes normal packet delivery BEFORE any recovery (e.g.
    // restarting SNIFF) runs. `WinDivert` has no Drop impl, so letting `wd` go
    // out of scope would NOT release the handle — the filter would stay live and
    // the network would stay frozen. `CloseAction::Nothing` keeps the driver
    // installed for the subsequent SNIFF handle.
    if let Err(e) = wd.close(windivert::CloseAction::Nothing) {
        tracing::error!("WinDivert close failed on intercept exit: {e}");
    }

    tracing::info!("WinDivert INTERCEPT capture stopped");

    // Only an unexpected death triggers app-layer recovery. Intentional
    // shutdown (BreakCleanly) leaves teardown to the caller that requested it.
    if intercept_exit_should_recover(exit_action) {
        on_unexpected_exit();
    }
}

pub(crate) fn process_sniff_packet(
    mapper: &ProcessMapper,
    tracker: &TrafficTracker,
    data: &[u8],
    outbound: bool,
) {
    let Some((proto, src_port, dst_port, total_len)) = parse_ip_packet(data) else {
        return;
    };

    let local_port = if outbound { src_port } else { dst_port };

    if let Some(pid) = mapper.lookup_pid(proto, local_port) {
        if outbound {
            tracker.record_bytes(pid, total_len, 0);
        } else {
            tracker.record_bytes(pid, 0, total_len);
        }
    }
}

/// Decide whether a packet should be passed or dropped.
/// Returns true (pass) for: unparseable packets, unknown PIDs, non-limited processes,
/// and rate-limited processes within their budget.
/// Returns false (drop) for: blocked PIDs and rate-limited processes over budget.
pub(crate) fn should_pass_packet(
    mapper: &ProcessMapper,
    rate_limiter: &RateLimiterManager,
    data: &[u8],
    outbound: bool,
) -> bool {
    let Some((proto, src_port, dst_port, total_len)) = parse_ip_packet(data) else {
        return true; // can't parse → pass through safely
    };

    let local_port = if outbound { src_port } else { dst_port };

    let Some(pid) = mapper.lookup_pid(proto, local_port) else {
        return true; // unknown PID → pass through
    };

    rate_limiter.should_pass_packet(pid, total_len, outbound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::mod_test_helpers::build_ipv4_packet;

    #[test]
    fn test_intercept_recv_buffer_covers_windivert_mtu_max() {
        // Bind to a local so clippy doesn't fold this into a const assertion;
        // the intent is a real regression guard on the buffer size constant.
        let windivert_mtu_max = std::hint::black_box(65_575usize);
        assert!(
            INTERCEPT_RECV_BUFFER_BYTES >= windivert_mtu_max,
            "INTERCEPT recv buffer must cover WINDIVERT_MTU_MAX"
        );
    }

    #[test]
    fn test_intercept_recv_error_policy_shutdown_breaks() {
        assert_eq!(
            classify_intercept_recv_error("NoData 232"),
            InterceptRecvErrorAction::BreakCleanly
        );
    }

    #[test]
    fn test_intercept_recv_error_policy_unknown_fails_open() {
        assert_eq!(
            classify_intercept_recv_error("ERROR_INSUFFICIENT_BUFFER 122"),
            InterceptRecvErrorAction::BreakFailOpen
        );
        assert_eq!(
            classify_intercept_recv_error("unexpected recv error"),
            InterceptRecvErrorAction::BreakFailOpen
        );
    }

    #[test]
    fn test_intercept_exit_recovery_only_on_fail_open() {
        // Intentional shutdown must NOT trigger recovery (no SNIFF restart / event).
        assert!(!intercept_exit_should_recover(
            InterceptRecvErrorAction::BreakCleanly
        ));
        // Unexpected death must trigger recovery (drop handle + restart SNIFF + emit).
        assert!(intercept_exit_should_recover(
            InterceptRecvErrorAction::BreakFailOpen
        ));
    }

    #[test]
    fn test_sniff_outbound_records_upload() {
        let mapper = ProcessMapper::new();
        let tracker = TrafficTracker::new();
        mapper
            .port_map
            .insert((crate::core::process_mapper::Protocol::Tcp, 12345), 42);

        let pkt = build_ipv4_packet(6, 12345, 443);
        process_sniff_packet(&mapper, &tracker, &pkt, true); // outbound

        let snap = tracker.snapshot(&mapper);
        let proc = snap.iter().find(|s| s.pid == 42);
        assert!(proc.is_some(), "PID 42 should appear in snapshot");
        assert!(
            proc.unwrap().bytes_sent > 0,
            "outbound bytes should be recorded as sent"
        );
        assert_eq!(proc.unwrap().bytes_recv, 0);
    }

    #[test]
    fn test_sniff_inbound_records_download() {
        let mapper = ProcessMapper::new();
        let tracker = TrafficTracker::new();
        mapper
            .port_map
            .insert((crate::core::process_mapper::Protocol::Tcp, 443), 42);

        let pkt = build_ipv4_packet(6, 12345, 443);
        process_sniff_packet(&mapper, &tracker, &pkt, false); // inbound

        let snap = tracker.snapshot(&mapper);
        let proc = snap.iter().find(|s| s.pid == 42);
        assert!(proc.is_some(), "PID 42 should appear in snapshot");
        assert_eq!(proc.unwrap().bytes_sent, 0);
        assert!(
            proc.unwrap().bytes_recv > 0,
            "inbound bytes should be recorded as recv"
        );
    }

    #[test]
    fn test_sniff_malformed_packet_no_panic() {
        let mapper = ProcessMapper::new();
        let tracker = TrafficTracker::new();
        process_sniff_packet(&mapper, &tracker, &[0xFF, 0x00], true);
        assert!(tracker.snapshot(&mapper).is_empty());
    }

    #[test]
    fn test_sniff_unknown_pid_no_record() {
        let mapper = ProcessMapper::new();
        let tracker = TrafficTracker::new();
        let pkt = build_ipv4_packet(6, 9999, 80);
        process_sniff_packet(&mapper, &tracker, &pkt, true);
        assert!(tracker.snapshot(&mapper).is_empty());
    }

    #[test]
    fn test_sniff_empty_packet_no_panic() {
        let mapper = ProcessMapper::new();
        let tracker = TrafficTracker::new();
        process_sniff_packet(&mapper, &tracker, &[], true);
        assert!(tracker.snapshot(&mapper).is_empty());
    }

    #[test]
    fn test_should_pass_unparseable_returns_true() {
        let mapper = ProcessMapper::new();
        let limiter = RateLimiterManager::new();
        assert!(should_pass_packet(&mapper, &limiter, &[0xFF], true));
    }

    #[test]
    fn test_should_pass_unknown_pid_returns_true() {
        let mapper = ProcessMapper::new();
        let limiter = RateLimiterManager::new();
        let pkt = build_ipv4_packet(6, 9999, 80);
        assert!(should_pass_packet(&mapper, &limiter, &pkt, true));
    }

    #[test]
    fn test_should_pass_no_limit_returns_true() {
        let mapper = ProcessMapper::new();
        let limiter = RateLimiterManager::new();
        mapper
            .port_map
            .insert((crate::core::process_mapper::Protocol::Tcp, 5000), 42);
        let pkt = build_ipv4_packet(6, 5000, 80);
        assert!(should_pass_packet(&mapper, &limiter, &pkt, true));
    }

    #[test]
    fn test_should_pass_blocked_pid_returns_false() {
        let mapper = ProcessMapper::new();
        let limiter = RateLimiterManager::new();
        mapper
            .port_map
            .insert((crate::core::process_mapper::Protocol::Tcp, 5000), 42);
        limiter.block_process(42);
        let pkt = build_ipv4_packet(6, 5000, 80);
        assert!(!should_pass_packet(&mapper, &limiter, &pkt, true));
    }

    #[test]
    fn test_should_pass_within_rate_budget() {
        let mapper = ProcessMapper::new();
        let limiter = RateLimiterManager::new();
        mapper
            .port_map
            .insert((crate::core::process_mapper::Protocol::Tcp, 5000), 42);
        limiter.set_limit(
            42,
            crate::core::rate_limiter::BandwidthLimit {
                download_bps: 1_000_000,
                upload_bps: 1_000_000,
            },
        );
        let pkt = build_ipv4_packet(6, 5000, 80);
        assert!(should_pass_packet(&mapper, &limiter, &pkt, true));
    }
}
