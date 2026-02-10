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

    let wd = WinDivert::network(filter, 0, flags)
        .context("Failed to open WinDivert handle — is the app running as administrator?")?;

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

                // Apply rate limiting — compute delay.
                let delay_ms = compute_packet_delay(
                    &process_mapper,
                    &rate_limiter,
                    &packet.data,
                    outbound,
                );

                if delay_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                }

                // Re-inject the packet back into the network stack.
                if let Err(e) = wd.send(&packet) {
                    tracing::error!("WinDivert send error: {e}");
                }
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

fn compute_packet_delay(
    mapper: &ProcessMapper,
    rate_limiter: &RateLimiterManager,
    data: &[u8],
    outbound: bool,
) -> u64 {
    let Some((proto, src_port, dst_port, total_len)) = parse_ip_packet(data) else {
        return 0;
    };

    let local_port = if outbound { src_port } else { dst_port };

    let Some(pid) = mapper.lookup_pid(proto, local_port) else {
        return 0;
    };

    rate_limiter.consume(pid, total_len, outbound)
}
