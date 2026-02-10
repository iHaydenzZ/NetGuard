//! Windows packet capture using WinDivert 2.x.
//!
//! Supports two modes:
//! - SNIFF: read-only packet copies for monitoring (Phase 1, zero risk)
//! - INTERCEPT: captures and re-injects packets for rate limiting (Phase 2+)
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

/// Main SNIFF capture loop running in a dedicated OS thread.
/// Packets are copied, never intercepted — zero risk to network connectivity.
pub fn run_sniff_loop(
    process_mapper: Arc<ProcessMapper>,
    traffic_tracker: Arc<TrafficTracker>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let filter = "tcp or udp";
    let flags = WinDivertFlags::new().set_sniff();

    tracing::info!("Opening WinDivert handle with filter: {filter}");
    let wd = WinDivert::network(filter, 0, flags).map_err(|e| {
        tracing::error!("WinDivert::network() failed: {e:?}");
        anyhow::anyhow!(
            "Failed to open WinDivert handle (filter={filter}): {e:?}. \
             Ensure WinDivert.dll and WinDivert64.sys are next to the executable \
             and the app is running as administrator."
        )
    })?;

    tracing::info!("WinDivert SNIFF capture started with filter: {filter}");

    let mut buf = vec![0u8; 65535];

    while !shutdown.load(Ordering::Relaxed) {
        match wd.recv(Some(&mut buf)) {
            Ok(packet) => {
                let outbound = packet.address.outbound();
                process_sniff_packet(
                    &process_mapper,
                    &traffic_tracker,
                    &packet.data,
                    outbound,
                );
            }
            Err(e) => {
                if shutdown.load(Ordering::Relaxed) {
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
/// SAFETY: Uses a narrow filter (specific port) during Phase 2a development.
/// See PRD S2 — never use "tcp or udp" in intercept mode during development.
pub fn run_intercept_loop(
    process_mapper: Arc<ProcessMapper>,
    traffic_tracker: Arc<TrafficTracker>,
    rate_limiter: Arc<RateLimiterManager>,
    shutdown: Arc<AtomicBool>,
    filter: &str,
) -> Result<()> {
    let flags = WinDivertFlags::new(); // default = intercept mode

    let wd = WinDivert::network(filter, 0, flags)
        .context("Failed to open WinDivert handle for intercept mode")?;

    tracing::info!("WinDivert INTERCEPT capture started with filter: {filter}");

    let mut buf = vec![0u8; 65535];

    while !shutdown.load(Ordering::Relaxed) {
        match wd.recv(Some(&mut buf)) {
            Ok(packet) => {
                let outbound = packet.address.outbound();

                // Account traffic (same as SNIFF mode).
                process_sniff_packet(
                    &process_mapper,
                    &traffic_tracker,
                    &packet.data,
                    outbound,
                );

                // Decide: pass or drop.
                // Non-rate-limited / non-blocked packets pass immediately.
                // Blocked or over-budget packets are silently dropped.
                if should_pass_packet(
                    &process_mapper,
                    &rate_limiter,
                    &packet.data,
                    outbound,
                ) {
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
                tracing::error!("WinDivert recv error in intercept mode: {e}");
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    tracing::info!("WinDivert INTERCEPT capture stopped");
    Ok(())
}

fn process_sniff_packet(
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
fn should_pass_packet(
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
