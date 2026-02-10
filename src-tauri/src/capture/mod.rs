//! Platform-specific packet capture backends.
//!
//! Each platform implements capture + re-injection:
//! - Windows: WinDivert 2.x (`windivert_backend`)
//! - macOS: pf + dnctl (`pf_backend`)

#[cfg(target_os = "windows")]
pub mod windivert_backend;

#[cfg(target_os = "macos")]
pub mod pf_backend;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::core::process_mapper::{ProcessMapper, Protocol};
use crate::core::rate_limiter::RateLimiterManager;
use crate::core::traffic::TrafficTracker;

/// Capture operating mode.
#[derive(Debug, Clone)]
pub enum CaptureMode {
    /// Read-only packet copies — zero risk (Phase 1).
    Sniff,
    /// Intercept and re-inject — enables rate limiting (Phase 2+).
    /// The string is the WinDivert filter to use.
    Intercept(String),
}

/// Manages a background packet capture thread.
/// Implements Drop to release resources on panic/exit (PRD safety invariant S4).
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
                    tracing::error!("WinDivert SNIFF capture loop exited: {e:#}");
                }
            })?;

        tracing::info!("CaptureEngine started in SNIFF mode");
        Ok(Self {
            shutdown,
            _capture_thread: Some(thread),
        })
    }

    /// Start capturing in INTERCEPT mode for rate limiting (Phase 2).
    /// `filter` should be a narrow WinDivert filter (e.g. port 5201 only).
    #[cfg(target_os = "windows")]
    pub fn start_intercept(
        process_mapper: Arc<ProcessMapper>,
        traffic_tracker: Arc<TrafficTracker>,
        rate_limiter: Arc<RateLimiterManager>,
        filter: String,
    ) -> anyhow::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let thread = std::thread::Builder::new()
            .name("windivert-intercept".into())
            .spawn(move || {
                if let Err(e) = windivert_backend::run_intercept_loop(
                    process_mapper,
                    traffic_tracker,
                    rate_limiter,
                    shutdown_clone,
                    &filter,
                ) {
                    tracing::error!("WinDivert INTERCEPT capture loop exited: {e}");
                }
            })?;

        tracing::info!("CaptureEngine started in INTERCEPT mode");
        Ok(Self {
            shutdown,
            _capture_thread: Some(thread),
        })
    }

    /// Start monitoring in SNIFF mode on macOS.
    ///
    /// On macOS, sniff mode is a no-op for packet capture. Traffic monitoring
    /// is handled entirely by the process_mapper (sysinfo network stats) and
    /// the traffic_tracker in the core layer. pf does not have a clean
    /// sniff-only mode equivalent to WinDivert's SNIFF flag.
    #[cfg(target_os = "macos")]
    pub fn start_sniff(
        _process_mapper: Arc<ProcessMapper>,
        _traffic_tracker: Arc<TrafficTracker>,
    ) -> anyhow::Result<Self> {
        pf_backend::start_sniff()?;

        tracing::info!("CaptureEngine started in SNIFF mode (macOS — process-scan only)");
        Ok(Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            _capture_thread: None,
        })
    }

    /// Start the intercept mode on macOS using pf + dummynet.
    ///
    /// Spawns a background thread that periodically syncs pf/dnctl rules
    /// with the RateLimiterManager state. The `filter` parameter is ignored
    /// on macOS (pf uses port-based rules derived from process_mapper).
    #[cfg(target_os = "macos")]
    pub fn start_intercept(
        process_mapper: Arc<ProcessMapper>,
        _traffic_tracker: Arc<TrafficTracker>,
        rate_limiter: Arc<RateLimiterManager>,
        _filter: String,
    ) -> anyhow::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);
        let pf_handle = pf_backend::PfHandle::new();

        let thread = std::thread::Builder::new()
            .name("pf-intercept-sync".into())
            .spawn(move || {
                if let Err(e) = pf_backend::run_intercept_sync_loop(
                    pf_handle,
                    process_mapper,
                    rate_limiter,
                    shutdown_clone,
                ) {
                    tracing::error!("pf INTERCEPT sync loop exited: {e}");
                }
            })?;

        tracing::info!("CaptureEngine started in INTERCEPT mode (macOS — pf + dnctl)");
        Ok(Self {
            shutdown,
            _capture_thread: Some(thread),
        })
    }

    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

impl Drop for CaptureEngine {
    fn drop(&mut self) {
        tracing::warn!("CaptureEngine dropped — releasing capture resources");
        self.shutdown.store(true, Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::process_mapper::Protocol;

    /// Build a minimal valid IPv4 packet with the given protocol byte and transport ports.
    /// Returns a Vec<u8> with: 20-byte IPv4 header + 4 bytes for src_port + dst_port.
    fn build_ipv4_packet(protocol: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let total_length: u16 = 24; // 20 (IP header) + 4 (ports minimum)
        let mut pkt = vec![0u8; total_length as usize];

        // Byte 0: version (4) in high nibble, IHL (5 = 20 bytes) in low nibble.
        pkt[0] = 0x45;
        // Bytes 2-3: total length in big-endian.
        pkt[2] = (total_length >> 8) as u8;
        pkt[3] = (total_length & 0xFF) as u8;
        // Byte 9: protocol.
        pkt[9] = protocol;
        // Bytes 20-21: source port (big-endian).
        pkt[20] = (src_port >> 8) as u8;
        pkt[21] = (src_port & 0xFF) as u8;
        // Bytes 22-23: destination port (big-endian).
        pkt[22] = (dst_port >> 8) as u8;
        pkt[23] = (dst_port & 0xFF) as u8;

        pkt
    }

    /// Build a minimal valid IPv6 packet with the given next_header (protocol) and transport ports.
    /// Returns a Vec<u8> with: 40-byte IPv6 header + 4 bytes for src_port + dst_port.
    fn build_ipv6_packet(next_header: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let payload_length: u16 = 4; // just the 4 port bytes
        let total_length = 40 + payload_length as usize;
        let mut pkt = vec![0u8; total_length];

        // Byte 0: version (6) in high nibble.
        pkt[0] = 0x60;
        // Bytes 4-5: payload length (big-endian).
        pkt[4] = (payload_length >> 8) as u8;
        pkt[5] = (payload_length & 0xFF) as u8;
        // Byte 6: next header (protocol).
        pkt[6] = next_header;
        // Bytes 40-41: source port (big-endian).
        pkt[40] = (src_port >> 8) as u8;
        pkt[41] = (src_port & 0xFF) as u8;
        // Bytes 42-43: destination port (big-endian).
        pkt[42] = (dst_port >> 8) as u8;
        pkt[43] = (dst_port & 0xFF) as u8;

        pkt
    }

    #[test]
    fn test_parse_empty_packet() {
        assert!(parse_ip_packet(&[]).is_none());
    }

    #[test]
    fn test_parse_too_short_ipv4() {
        // 19 bytes — one short of the minimum 20-byte IPv4 header.
        let short = vec![0x45; 19];
        assert!(parse_ip_packet(&short).is_none());
    }

    #[test]
    fn test_parse_valid_tcp_ipv4() {
        let pkt = build_ipv4_packet(6, 12345, 443); // TCP = protocol 6
        let result = parse_ip_packet(&pkt);
        assert!(result.is_some());

        let (proto, src_port, dst_port, length) = result.unwrap();
        assert_eq!(proto, Protocol::Tcp);
        assert_eq!(src_port, 12345);
        assert_eq!(dst_port, 443);
        assert_eq!(length, 24); // total_length field in the header
    }

    #[test]
    fn test_parse_valid_udp_ipv4() {
        let pkt = build_ipv4_packet(17, 5353, 53); // UDP = protocol 17
        let result = parse_ip_packet(&pkt);
        assert!(result.is_some());

        let (proto, src_port, dst_port, length) = result.unwrap();
        assert_eq!(proto, Protocol::Udp);
        assert_eq!(src_port, 5353);
        assert_eq!(dst_port, 53);
        assert_eq!(length, 24);
    }

    #[test]
    fn test_parse_valid_tcp_ipv6() {
        let pkt = build_ipv6_packet(6, 8080, 80); // TCP = next_header 6
        let result = parse_ip_packet(&pkt);
        assert!(result.is_some());

        let (proto, src_port, dst_port, length) = result.unwrap();
        assert_eq!(proto, Protocol::Tcp);
        assert_eq!(src_port, 8080);
        assert_eq!(dst_port, 80);
        // IPv6 total = 40 (header) + payload_len (4) = 44
        assert_eq!(length, 44);
    }

    #[test]
    fn test_parse_unknown_protocol() {
        // ICMP = protocol byte 1, which parse_ip_packet does not handle.
        let pkt = build_ipv4_packet(1, 0, 0);
        assert!(parse_ip_packet(&pkt).is_none());
    }

    #[test]
    fn test_parse_truncated_transport() {
        // Build a valid 20-byte IPv4 header with TCP protocol, but NO transport bytes after it.
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[2] = 0;
        pkt[3] = 20; // total_length = 20
        pkt[9] = 6; // TCP

        // The parser requires header_len + 4 bytes for ports, so 24 bytes minimum.
        // We only have 20, so it should return None.
        assert!(parse_ip_packet(&pkt).is_none());
    }
}
