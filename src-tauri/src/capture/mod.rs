//! Platform-specific packet capture backends.
//!
//! Each platform implements the `PacketBackend` trait:
//! - Windows: WinDivert 2.x (`windivert_backend`)
//! - macOS: pf + dnctl (`pf_backend`)

#[cfg(target_os = "windows")]
pub mod windivert_backend;

#[cfg(target_os = "macos")]
pub mod pf_backend;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::core::process_mapper::{ProcessMapper, Protocol};
use crate::core::traffic::TrafficTracker;

/// Manages a background packet capture thread.
/// Implements Drop to release resources on panic/exit (safety invariant from PRD S4).
pub struct CaptureEngine {
    shutdown: Arc<AtomicBool>,
    _capture_thread: Option<std::thread::JoinHandle<()>>,
}

impl CaptureEngine {
    /// Start capturing in SNIFF mode (Phase 1 — zero-risk, read-only copies).
    #[cfg(target_os = "windows")]
    pub fn start_sniff(
        process_mapper: Arc<ProcessMapper>,
        traffic_tracker: Arc<TrafficTracker>,
    ) -> anyhow::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let thread = std::thread::Builder::new()
            .name("windivert-sniff".into())
            .spawn(move || {
                if let Err(e) = windivert_backend::run_sniff_loop(
                    process_mapper,
                    traffic_tracker,
                    shutdown_clone,
                ) {
                    tracing::error!("WinDivert capture loop exited with error: {e}");
                }
            })?;

        tracing::info!("CaptureEngine started in SNIFF mode");
        Ok(Self {
            shutdown,
            _capture_thread: Some(thread),
        })
    }

    /// macOS stub — Phase 3.
    #[cfg(target_os = "macos")]
    pub fn start_sniff(
        _process_mapper: Arc<ProcessMapper>,
        _traffic_tracker: Arc<TrafficTracker>,
    ) -> anyhow::Result<Self> {
        tracing::warn!("macOS capture not yet implemented (Phase 3)");
        Ok(Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            _capture_thread: None,
        })
    }
}

impl Drop for CaptureEngine {
    fn drop(&mut self) {
        tracing::warn!("CaptureEngine dropped — releasing capture resources");
        self.shutdown.store(true, Ordering::Relaxed);
        // In SNIFF mode this is harmless: no packets are intercepted.
        // The WinDivert handle inside the thread will be dropped when recv returns an error
        // or when the thread exits naturally.
    }
}

/// Parse an IP packet and extract protocol + src/dst ports.
/// Returns (protocol, src_port, dst_port, packet_length).
pub fn parse_ip_packet(data: &[u8]) -> Option<(Protocol, u16, u16, u64)> {
    if data.is_empty() {
        return None;
    }

    let version = data[0] >> 4;
    let (protocol_byte, header_len, total_len) = match version {
        4 => {
            if data.len() < 20 {
                return None;
            }
            let ihl = ((data[0] & 0x0F) as usize) * 4;
            let total = u16::from_be_bytes([data[2], data[3]]) as u64;
            (data[9], ihl, total)
        }
        6 => {
            if data.len() < 40 {
                return None;
            }
            let payload_len = u16::from_be_bytes([data[4], data[5]]) as u64;
            (data[6], 40, payload_len + 40)
        }
        _ => return None,
    };

    let proto = match protocol_byte {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return None,
    };

    if data.len() < header_len + 4 {
        return None;
    }

    let src_port = u16::from_be_bytes([data[header_len], data[header_len + 1]]);
    let dst_port = u16::from_be_bytes([data[header_len + 2], data[header_len + 3]]);

    Some((proto, src_port, dst_port, total_len))
}
