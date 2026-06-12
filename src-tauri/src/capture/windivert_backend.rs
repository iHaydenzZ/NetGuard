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

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use windivert::prelude::*;

use crate::capture::parse_ip_packet;
use crate::core::process_mapper::ProcessMapper;
use crate::core::rate_limiter::RateLimiterManager;
use crate::core::traffic::TrafficTracker;

/// WinDivert filter used for SNIFF (read-only) mode. Shares the canonical
/// definition in `config` with the intercept default so monitoring and
/// enforcement always see the same traffic.
///
/// NOTE: iperf3 smoke tests on localhost (127.0.0.1) are excluded by this
/// filter (`not loopback`). Use a custom filter or a remote iperf3 endpoint
/// for local tests. See CLAUDE.md "Test Tools" for details.
pub(crate) const SNIFF_FILTER: &str = crate::config::DEFAULT_CAPTURE_FILTER;

/// Recv buffer size in intercept mode. Must cover WINDIVERT_MTU_MAX so a
/// maximum-size packet is never truncated; a truncated re-injected packet
/// would corrupt the connection.
const INTERCEPT_RECV_BUFFER_BYTES: usize = crate::config::WINDIVERT_MTU_MAX_BYTES;

/// Recv buffer size in SNIFF mode. Read-only copies, but sized the same as the
/// intercept buffer for consistency and full-MTU coverage.
const SNIFF_RECV_BUFFER_BYTES: usize = crate::config::WINDIVERT_MTU_MAX_BYTES;

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
/// WinDivert raises `WinDivertRecvError::NoData` (Win32 error 232) when
/// `WinDivertShutdown` is called, which is our intentional stop path.
///
/// We match on the typed error variant rather than the Display string to avoid
/// false positives: substring matching on "232" would misclassify any error
/// whose message happens to contain "232" (e.g. a byte count, port, or PID)
/// as a clean shutdown, silently suppressing fail-open recovery — the
/// worst-direction failure for a fail-open safety invariant.
fn classify_intercept_recv_error(err: &WinDivertError) -> InterceptRecvErrorAction {
    if matches!(err, WinDivertError::Recv(WinDivertRecvError::NoData)) {
        InterceptRecvErrorAction::BreakCleanly
    } else {
        InterceptRecvErrorAction::BreakFailOpen
    }
}

/// Returns true if a SNIFF recv error is the expected clean-shutdown signal.
///
/// Uses typed matching for the same reason as `classify_intercept_recv_error`:
/// substring matching on "232" is brittle.
fn is_sniff_shutdown_error(err: &WinDivertError) -> bool {
    matches!(err, WinDivertError::Recv(WinDivertRecvError::NoData))
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

/// The panic payload type produced by `catch_unwind` (a boxed `Any`).
type PanicPayload = Box<dyn std::any::Any + Send>;

/// Unify the intercept loop's exit into a single "should we recover?" decision.
///
/// - `Ok(action)`: the loop returned normally — defer to the recv-error policy.
/// - `Err(_)`: the loop body panicked. A panic is an unexpected death (same
///   class as `BreakFailOpen`): the loop is no longer pumping packets, so the
///   live divert handle would drop everything it receives. We MUST recover
///   (close handle already done by the caller, then restart SNIFF + notify UI).
fn exit_disposition(result: &Result<InterceptRecvErrorAction, PanicPayload>) -> bool {
    match result {
        Ok(action) => intercept_exit_should_recover(*action),
        Err(_) => true,
    }
}

/// Best-effort extraction of a human-readable message from a panic payload.
///
/// Rust panics carry either a `String` (formatted `panic!("{}", x)`) or a
/// `&'static str` (literal `panic!("msg")`); anything else is opaque. We try
/// both common downcasts and fall back to a placeholder so the log line is
/// never empty.
fn panic_payload_message(payload: &PanicPayload) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// Create a WinDivert handle in SNIFF mode (read-only packet copies).
pub fn create_sniff_handle() -> Result<WinDivert<windivert::layer::NetworkLayer>> {
    let filter = SNIFF_FILTER;
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
/// No `catch_unwind` guard here (unlike `run_intercept_loop`): the SNIFF handle
/// is read-only, so a panic that drops it only leaks the handle and loses
/// monitoring — it cannot freeze traffic, since nothing was diverted. The guard
/// is intercept-only by design; do not "fix" this asymmetry. Normal exits DO
/// `close()` explicitly below: the windivert crate has no Drop impl, so
/// returning without it would leak the OS handle and leave the SNIFF filter
/// installed on every monitoring stop (intercept toggle, app shutdown).
///
/// Accepts a pre-created WinDivert handle (created by `create_sniff_handle`).
pub fn run_sniff_loop(
    mut wd: WinDivert<windivert::layer::NetworkLayer>,
    process_mapper: Arc<ProcessMapper>,
    traffic_tracker: Arc<TrafficTracker>,
    shutdown: Arc<AtomicBool>,
    handle_released: Arc<AtomicBool>,
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
                // NoData means WinDivertShutdown was called — clean exit.
                if is_sniff_shutdown_error(&e) {
                    tracing::info!("WinDivert SNIFF recv got shutdown signal");
                    break;
                }
                tracing::error!("WinDivert recv error: {e}");
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    // Explicitly release the handle — `windivert` 0.6 has no Drop impl, so
    // falling out of scope would leak the OS handle and keep the SNIFF filter
    // installed (the driver keeps copying packets into a queue nobody drains)
    // for every stop/start cycle. `CloseAction::Nothing` keeps the driver
    // loaded for the next handle, matching the intercept loop's cleanup.
    match wd.close(windivert::CloseAction::Nothing) {
        // Flag only on success: a failed close leaves the handle open, and
        // Drop's WinDivertShutdown is then still the right fallback.
        Ok(()) => handle_released.store(true, Ordering::Release),
        Err(e) => tracing::error!("WinDivert close failed on SNIFF exit: {e}"),
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
    handle_released: Arc<AtomicBool>,
    on_unexpected_exit: Box<dyn FnOnce() + Send>,
) {
    tracing::info!("WinDivert INTERCEPT capture loop started");

    // Run the recv/send loop under `catch_unwind`. WinDivert 0.6 has NO `Drop`
    // impl (verified against crate source), so a panic that unwound past this
    // frame would drop `wd` WITHOUT releasing the OS handle — the divert filter
    // would stay installed and FREEZE the host network until process exit. By
    // catching the unwind here we guarantee the explicit `wd.close()` below runs
    // on the panic path too, restoring normal delivery (fail-open invariant).
    //
    // `wd` and `on_unexpected_exit` stay OUTSIDE the closure: the closure only
    // borrows `&wd` (recv/send take `&self`), so its borrow ends before the
    // `&mut wd` `close()` below. `AssertUnwindSafe` is justified because on
    // panic we do not resume using the captured state except for the cleanup
    // path (close + recovery callback); the shared structures are `parking_lot`
    // mutexes / `DashMap`, neither of which poisons, so they remain usable by
    // other threads regardless of where this loop panicked.
    let result: Result<InterceptRecvErrorAction, PanicPayload> =
        std::panic::catch_unwind(AssertUnwindSafe(|| {
            intercept_recv_loop(
                &wd,
                &process_mapper,
                &traffic_tracker,
                &rate_limiter,
                &shutdown,
            )
        }));

    // Explicitly close the divert handle so the driver uninstalls the filter
    // and the OS resumes normal packet delivery BEFORE any recovery (e.g.
    // restarting SNIFF) runs. `WinDivert` has no Drop impl, so letting `wd` go
    // out of scope would NOT release the handle — the filter would stay live and
    // the network would stay frozen. `CloseAction::Nothing` keeps the driver
    // installed for the subsequent SNIFF handle. This runs on BOTH the normal
    // and the caught-panic path.
    match wd.close(windivert::CloseAction::Nothing) {
        Ok(()) => handle_released.store(true, Ordering::Release),
        Err(e) => tracing::error!("WinDivert close failed on intercept exit: {e}"),
    }

    if let Err(payload) = &result {
        tracing::error!(
            "WinDivert INTERCEPT loop panicked; closed handle to fail open: {}",
            panic_payload_message(payload)
        );
    }

    tracing::info!("WinDivert INTERCEPT capture stopped");

    // An unexpected death triggers app-layer recovery: an unknown recv error
    // (BreakFailOpen) OR a panic. Intentional shutdown (BreakCleanly) leaves
    // teardown to the caller that requested it.
    if exit_disposition(&result) {
        on_unexpected_exit();
    }
}

/// The intercept recv/send loop body, isolated so it can run under
/// `catch_unwind` while `close()` (which needs `&mut wd`) stays in the caller.
///
/// Takes `&wd` only — `recv`/`send` are `&self` on WinDivert's NetworkLayer.
/// Returns the recv-error disposition (`BreakCleanly` for the intentional
/// shutdown signal, `BreakFailOpen` for an unknown error). A panic inside this
/// fn unwinds to the caller's `catch_unwind`, which then closes the handle.
fn intercept_recv_loop(
    wd: &WinDivert<windivert::layer::NetworkLayer>,
    process_mapper: &ProcessMapper,
    traffic_tracker: &TrafficTracker,
    rate_limiter: &RateLimiterManager,
    shutdown: &AtomicBool,
) -> InterceptRecvErrorAction {
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
                process_sniff_packet(process_mapper, traffic_tracker, &packet.data, outbound);

                // Decide: pass or drop.
                // Non-rate-limited / non-blocked packets pass immediately.
                // Blocked or over-budget packets are silently dropped.
                if should_pass_packet(process_mapper, rate_limiter, &packet.data, outbound) {
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
                exit_action = classify_intercept_recv_error(&e);
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

    exit_action
}

pub(crate) fn process_sniff_packet(
    mapper: &ProcessMapper,
    tracker: &TrafficTracker,
    data: &[u8],
    outbound: bool,
) {
    let Some(parsed) = parse_ip_packet(data) else {
        return;
    };

    // The local endpoint is the source for outbound packets, destination for
    // inbound — that is the side owned by a local process.
    let local_endpoint = if outbound { parsed.src } else { parsed.dst };

    if let Some(pid) = mapper.lookup_pid(&local_endpoint) {
        if outbound {
            tracker.record_bytes(pid, parsed.total_len, 0);
        } else {
            tracker.record_bytes(pid, 0, parsed.total_len);
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
    let Some(parsed) = parse_ip_packet(data) else {
        return true; // can't parse → pass through safely
    };

    let local_endpoint = if outbound { parsed.src } else { parsed.dst };

    let Some(pid) = mapper.lookup_pid(&local_endpoint) else {
        return true; // unknown PID → pass through
    };

    rate_limiter.should_pass_packet(pid, parsed.total_len, outbound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::mod_test_helpers::{build_ipv4_packet, TEST_DST_IPV4, TEST_SRC_IPV4};
    use crate::core::process_mapper::{LocalEndpoint, Protocol};

    /// Regression guard: SNIFF_FILTER must exclude loopback so local IPC traffic
    /// (DB connections, Tauri webview socket, dev servers on 127.0.0.1) is never
    /// captured, counted, or throttled. Without this guard, a careless edit that
    /// reverts the filter to `"tcp or udp"` would silently re-introduce the bug.
    #[test]
    fn test_sniff_filter_excludes_loopback() {
        assert!(
            SNIFF_FILTER.contains("not loopback"),
            "SNIFF_FILTER must exclude loopback traffic: {SNIFF_FILTER}"
        );
    }

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
        let err = WinDivertError::Recv(WinDivertRecvError::NoData);
        assert_eq!(
            classify_intercept_recv_error(&err),
            InterceptRecvErrorAction::BreakCleanly
        );
    }

    #[test]
    fn test_intercept_recv_error_policy_unknown_fails_open() {
        let insufficient_buf = WinDivertError::Recv(WinDivertRecvError::InsufficientBuffer);
        assert_eq!(
            classify_intercept_recv_error(&insufficient_buf),
            InterceptRecvErrorAction::BreakFailOpen
        );
        let io_err = WinDivertError::IOError(std::io::Error::from_raw_os_error(10));
        assert_eq!(
            classify_intercept_recv_error(&io_err),
            InterceptRecvErrorAction::BreakFailOpen
        );
    }

    /// Regression test: an error whose Display contains "232" but is NOT NoData
    /// must NOT be misclassified as a clean shutdown. The old substring-matching
    /// approach would have returned BreakCleanly here, silently suppressing
    /// fail-open recovery.
    #[test]
    fn test_intercept_recv_error_policy_display_232_not_nodata_fails_open() {
        // InsufficientBuffer is error 122; its Display does not contain "232",
        // but we use a raw OS error whose code is 232-adjacent to prove the
        // typed match is correct regardless of message content.
        // Raw OS error 1232 has "1232" in its message on some Windows builds —
        // substring "232" would match; typed match correctly returns BreakFailOpen.
        let err = WinDivertError::IOError(std::io::Error::from_raw_os_error(1232));
        assert_eq!(
            classify_intercept_recv_error(&err),
            InterceptRecvErrorAction::BreakFailOpen,
            "error containing '232' in its message must not be misclassified as clean shutdown"
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
    fn test_exit_disposition_clean_shutdown_no_recover() {
        let result: Result<InterceptRecvErrorAction, PanicPayload> =
            Ok(InterceptRecvErrorAction::BreakCleanly);
        assert!(
            !exit_disposition(&result),
            "intentional shutdown must not trigger recovery"
        );
    }

    #[test]
    fn test_exit_disposition_fail_open_recovers() {
        let result: Result<InterceptRecvErrorAction, PanicPayload> =
            Ok(InterceptRecvErrorAction::BreakFailOpen);
        assert!(
            exit_disposition(&result),
            "unknown recv error (fail-open) must trigger recovery"
        );
    }

    #[test]
    fn test_exit_disposition_panic_recovers() {
        // A panic is an unexpected death — same class as fail-open. The loop is
        // no longer pumping packets, so we must restart SNIFF and notify the UI.
        let result: Result<InterceptRecvErrorAction, PanicPayload> =
            Err(Box::new("boom") as PanicPayload);
        assert!(
            exit_disposition(&result),
            "a panicked intercept loop must trigger recovery"
        );
    }

    #[test]
    fn test_panic_payload_message_from_string() {
        // panic!("{}", String) yields a String payload.
        let payload: PanicPayload = Box::new(String::from("formatted panic"));
        assert_eq!(panic_payload_message(&payload), "formatted panic");
    }

    #[test]
    fn test_panic_payload_message_from_static_str() {
        // panic!("literal") yields a &'static str payload.
        let payload: PanicPayload = Box::new("literal panic");
        assert_eq!(panic_payload_message(&payload), "literal panic");
    }

    #[test]
    fn test_panic_payload_message_from_other_type_is_placeholder() {
        // Non-string payloads (e.g. panic_any(42)) are opaque; we must still
        // produce a non-empty, descriptive log message.
        let payload: PanicPayload = Box::new(42u32);
        assert_eq!(
            panic_payload_message(&payload),
            "<non-string panic payload>"
        );
    }

    /// End-to-end seam check: `catch_unwind` over a closure that panics yields an
    /// `Err` payload that `exit_disposition` maps to "recover", and the payload
    /// message is extractable. This exercises the real plumbing the intercept
    /// loop relies on without needing a WinDivert handle.
    #[test]
    fn test_caught_panic_maps_to_recover_with_message() {
        let result: Result<InterceptRecvErrorAction, PanicPayload> =
            std::panic::catch_unwind(AssertUnwindSafe(|| {
                panic!("simulated intercept loop panic");
            }));
        assert!(result.is_err(), "panic must be caught, not propagated");
        assert!(
            exit_disposition(&result),
            "caught panic must trigger recovery"
        );
        if let Err(payload) = &result {
            assert_eq!(
                panic_payload_message(payload),
                "simulated intercept loop panic"
            );
        }
    }

    #[test]
    fn test_sniff_outbound_records_upload() {
        let mapper = ProcessMapper::new();
        let tracker = TrafficTracker::new();
        mapper
            .port_map
            .insert(LocalEndpoint::ipv4(Protocol::Tcp, TEST_SRC_IPV4, 12345), 42);

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
            .insert(LocalEndpoint::ipv4(Protocol::Tcp, TEST_DST_IPV4, 443), 42);

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
            .insert(LocalEndpoint::ipv4(Protocol::Tcp, TEST_SRC_IPV4, 5000), 42);
        let pkt = build_ipv4_packet(6, 5000, 80);
        assert!(should_pass_packet(&mapper, &limiter, &pkt, true));
    }

    #[test]
    fn test_should_pass_blocked_pid_returns_false() {
        let mapper = ProcessMapper::new();
        let limiter = RateLimiterManager::new();
        mapper
            .port_map
            .insert(LocalEndpoint::ipv4(Protocol::Tcp, TEST_SRC_IPV4, 5000), 42);
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
            .insert(LocalEndpoint::ipv4(Protocol::Tcp, TEST_SRC_IPV4, 5000), 42);
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
