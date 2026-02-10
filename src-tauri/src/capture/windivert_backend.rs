//! Windows packet capture using WinDivert 2.x in SNIFF mode.
//!
//! SAFETY: This module intercepts live network packets.
//! Always use the narrowest possible filter during development.
//! See PRD section 8.2 for mandatory safeguards.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use windivert::prelude::*;

use crate::capture::parse_ip_packet;
use crate::core::process_mapper::ProcessMapper;
use crate::core::traffic::TrafficTracker;

/// Main capture loop running in a dedicated OS thread.
/// Uses SNIFF mode (Phase 1) — packets are copied, never intercepted.
/// Network connectivity is never affected regardless of bugs.
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
                process_packet(&process_mapper, &traffic_tracker, &packet.data, outbound);
            }
            Err(e) => {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                tracing::error!("WinDivert recv error: {e}");
                // Brief pause before retrying to avoid spinning on repeated errors.
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    tracing::info!("WinDivert SNIFF capture stopped");
    Ok(())
}

fn process_packet(
    mapper: &ProcessMapper,
    tracker: &TrafficTracker,
    data: &[u8],
    outbound: bool,
) {
    let Some((proto, src_port, dst_port, total_len)) = parse_ip_packet(data) else {
        return;
    };

    // In SNIFF mode on the local machine:
    // - outbound packets: local port = src_port
    // - inbound packets: local port = dst_port
    let local_port = if outbound { src_port } else { dst_port };

    if let Some(pid) = mapper.lookup_pid(proto, local_port) {
        if outbound {
            tracker.record_bytes(pid, total_len, 0);
        } else {
            tracker.record_bytes(pid, 0, total_len);
        }
    }
}
