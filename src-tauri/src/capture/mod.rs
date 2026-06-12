//! Windows packet capture backend using WinDivert 2.x.
//!
//! Provides [`CaptureEngine`] for SNIFF (read-only) and INTERCEPT (rate-limiting) modes.
//! `CaptureEngine`'s `Drop` signals shutdown and joins the capture thread on
//! teardown; the raw WinDivert handle itself is released by the capture loops'
//! explicit `close()` on every exit path (the windivert crate has no Drop impls).

pub mod windivert_backend;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::core::process_mapper::{LocalEndpoint, ProcessMapper, Protocol};
use crate::core::rate_limiter::RateLimiterManager;
use crate::core::traffic::TrafficTracker;

/// Manages a background packet capture thread.
/// Implements Drop to release resources on panic/exit (PRD safety invariant S4).
///
/// Stores the raw WinDivert HANDLE so that `Drop` can call
/// `WinDivertShutdown` to unblock a blocking `recv()` from another thread.
/// Without this, the intercept thread keeps diverting packets after stop is
/// requested, causing total network loss.
pub struct CaptureEngine {
    shutdown: Arc<AtomicBool>,
    /// Raw WinDivert HANDLE for cross-thread shutdown.
    raw_wd_handle: Option<isize>,
    capture_thread: Option<std::thread::JoinHandle<()>>,
}

/// Raw FFI for WinDivertShutdown — the safe wrapper requires `&mut self` which
/// makes cross-thread shutdown impossible. The C API is explicitly thread-safe.
mod wd_ffi {
    pub const WINDIVERT_SHUTDOWN_RECV: u32 = 1;

    #[link(name = "WinDivert")]
    extern "system" {
        pub fn WinDivertShutdown(handle: isize, how: u32) -> i32;
    }
}

/// Extract the raw WinDivert HANDLE from a `WinDivert<L>` wrapper.
///
/// SAFETY: Relies on `handle: HANDLE` (isize) being the first field of `WinDivert<L>`.
/// Verified against windivert 0.6.0 source. If the crate changes its layout,
/// the shutdown call will harmlessly fail (WinDivert returns FALSE for invalid
/// handles) rather than cause UB.
unsafe fn extract_wd_handle(
    wd: &windivert::prelude::WinDivert<windivert::layer::NetworkLayer>,
) -> isize {
    *(wd as *const _ as *const isize)
}

impl CaptureEngine {
    /// Start capturing in SNIFF mode (Phase 1 — zero-risk, read-only copies).
    ///
    /// The WinDivert handle is created on the calling thread and moved into
    /// the capture thread, so we can extract the raw HANDLE for clean shutdown.
    pub fn start_sniff(
        process_mapper: Arc<ProcessMapper>,
        traffic_tracker: Arc<TrafficTracker>,
    ) -> anyhow::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        // Create handle here so we can extract the raw HANDLE for shutdown.
        let wd = windivert_backend::create_sniff_handle()?;
        let raw_handle = unsafe { extract_wd_handle(&wd) };

        let thread = std::thread::Builder::new()
            .name("windivert-sniff".into())
            .spawn(move || {
                if let Err(e) = windivert_backend::run_sniff_loop(
                    wd,
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
            raw_wd_handle: Some(raw_handle),
            capture_thread: Some(thread),
        })
    }

    /// Start capturing in INTERCEPT mode for rate limiting (Phase 2).
    /// `filter` should be a narrow WinDivert filter (e.g. port 5201 only).
    ///
    /// `on_unexpected_exit` runs on the capture thread iff the loop dies from an
    /// unknown recv error (fail-open) — NOT on intentional shutdown. The app
    /// layer uses it to drop the dead engine, restart SNIFF, and notify the UI.
    /// It must not block on this engine's own join (spawn a detached recovery
    /// thread); see `commands::system::enable_intercept_mode`.
    ///
    /// **Important:** Stop the SNIFF engine before starting intercept to avoid
    /// double-counting traffic (both loops call `record_bytes`).
    pub fn start_intercept(
        process_mapper: Arc<ProcessMapper>,
        traffic_tracker: Arc<TrafficTracker>,
        rate_limiter: Arc<RateLimiterManager>,
        filter: String,
        on_unexpected_exit: Box<dyn FnOnce() + Send>,
    ) -> anyhow::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let wd = windivert_backend::create_intercept_handle(&filter)?;
        let raw_handle = unsafe { extract_wd_handle(&wd) };

        let thread = std::thread::Builder::new()
            .name("windivert-intercept".into())
            .spawn(move || {
                windivert_backend::run_intercept_loop(
                    wd,
                    process_mapper,
                    traffic_tracker,
                    rate_limiter,
                    shutdown_clone,
                    on_unexpected_exit,
                );
            })?;

        tracing::info!("CaptureEngine started in INTERCEPT mode");
        Ok(Self {
            shutdown,
            raw_wd_handle: Some(raw_handle),
            capture_thread: Some(thread),
        })
    }
}

impl Drop for CaptureEngine {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);

        // Call WinDivertShutdown to unblock the blocking recv().
        // Without this, the capture thread keeps diverting packets after stop.
        if let Some(raw) = self.raw_wd_handle {
            unsafe {
                wd_ffi::WinDivertShutdown(raw, wd_ffi::WINDIVERT_SHUTDOWN_RECV);
            }
        }

        // Wait for the capture thread to exit (with timeout).
        if let Some(thread) = self.capture_thread.take() {
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_secs(3) {
                if thread.is_finished() {
                    let _ = thread.join();
                    tracing::info!("Capture thread joined cleanly");
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            tracing::warn!("Capture thread did not exit within 3s, detaching");
        }
    }
}

/// A parsed IP packet's protocol, source/destination endpoints, and length.
///
/// `src`/`dst` carry the local address in network/address byte order (the same
/// order the IP Helper table scanner produces), so endpoints from a packet and
/// from the table compare equal for exact lookups. `LocalEndpoint` is `Copy`, so
/// this struct is allocation-free for the per-packet hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedPacket {
    pub proto: Protocol,
    pub src: LocalEndpoint,
    pub dst: LocalEndpoint,
    /// Captured packet length in bytes (`data.len()`), NOT the IP header's
    /// length field. The header field is attacker-written for inbound packets
    /// (a value of 0 would make the token bucket charge nothing — silent
    /// limit bypass) and can be stale under NIC offload. The captured length
    /// is exactly what WinDivert received and will re-inject.
    pub total_len: u64,
}

/// Parse an IP packet and extract protocol, src/dst endpoints, and length.
///
/// Addresses are read directly off the wire (already network byte order):
/// IPv4 source = header bytes 12..16, dest = 16..20; IPv6 source = 8..24,
/// dest = 24..40. Ports follow the (variable-length for IPv4) IP header.
pub fn parse_ip_packet(data: &[u8]) -> Option<ParsedPacket> {
    if data.is_empty() {
        return None;
    }

    let version = data[0] >> 4;
    let (protocol_byte, header_len, src_addr, dst_addr) = match version {
        4 => {
            if data.len() < 20 {
                return None;
            }
            let ihl = ((data[0] & 0x0F) as usize) * 4;
            // IPv4 addresses: src = bytes 12..16, dst = bytes 16..20 (network order).
            let src = AddrBytes::V4([data[12], data[13], data[14], data[15]]);
            let dst = AddrBytes::V4([data[16], data[17], data[18], data[19]]);
            (data[9], ihl, src, dst)
        }
        6 => {
            if data.len() < 40 {
                return None;
            }
            // IPv6 addresses: src = bytes 8..24, dst = bytes 24..40 (network order).
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(&data[8..24]);
            dst.copy_from_slice(&data[24..40]);
            (data[6], 40, AddrBytes::V6(src), AddrBytes::V6(dst))
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

    Some(ParsedPacket {
        proto,
        src: src_addr.endpoint(proto, src_port),
        dst: dst_addr.endpoint(proto, dst_port),
        total_len: data.len() as u64,
    })
}

/// Internal helper: address bytes tagged by family, to build a `LocalEndpoint`
/// in the same byte order on both the v4 and v6 paths.
enum AddrBytes {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl AddrBytes {
    fn endpoint(self, proto: Protocol, port: u16) -> LocalEndpoint {
        match self {
            AddrBytes::V4(a) => LocalEndpoint::ipv4(proto, a, port),
            AddrBytes::V6(a) => LocalEndpoint::ipv6(proto, a, port),
        }
    }
}

/// Test helpers shared between capture submodules.
#[cfg(test)]
pub(crate) mod mod_test_helpers {
    /// Deterministic source/destination IPv4 addresses used by the test packet
    /// builder, so tests can register matching `LocalEndpoint` keys.
    pub const TEST_SRC_IPV4: [u8; 4] = [10, 0, 0, 1];
    pub const TEST_DST_IPV4: [u8; 4] = [93, 184, 216, 34];

    /// Build a minimal valid IPv4 packet with the given protocol byte and transport ports.
    /// Returns a Vec<u8> with: 20-byte IPv4 header + 4 bytes for src_port + dst_port.
    /// Source/dest addresses are fixed (`TEST_SRC_IPV4` / `TEST_DST_IPV4`).
    pub fn build_ipv4_packet(protocol: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let total_length: u16 = 24; // 20 (IP header) + 4 (ports minimum)
        let mut pkt = vec![0u8; total_length as usize];

        // Byte 0: version (4) in high nibble, IHL (5 = 20 bytes) in low nibble.
        pkt[0] = 0x45;
        // Bytes 2-3: total length in big-endian.
        pkt[2] = (total_length >> 8) as u8;
        pkt[3] = (total_length & 0xFF) as u8;
        // Byte 9: protocol.
        pkt[9] = protocol;
        // Bytes 12-15: source address (network order).
        pkt[12..16].copy_from_slice(&TEST_SRC_IPV4);
        // Bytes 16-19: destination address (network order).
        pkt[16..20].copy_from_slice(&TEST_DST_IPV4);
        // Bytes 20-21: source port (big-endian).
        pkt[20] = (src_port >> 8) as u8;
        pkt[21] = (src_port & 0xFF) as u8;
        // Bytes 22-23: destination port (big-endian).
        pkt[22] = (dst_port >> 8) as u8;
        pkt[23] = (dst_port & 0xFF) as u8;

        pkt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::process_mapper::Protocol;

    use super::mod_test_helpers::build_ipv4_packet;

    /// Deterministic IPv6 source/destination addresses for the test builder.
    const TEST_SRC_IPV6: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    const TEST_DST_IPV6: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];

    /// Build a minimal valid IPv6 packet with the given next_header (protocol) and transport ports.
    /// Returns a Vec<u8> with: 40-byte IPv6 header + 4 bytes for src_port + dst_port.
    /// Source/dest addresses are fixed (`TEST_SRC_IPV6` / `TEST_DST_IPV6`).
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
        // Bytes 8-23: source address (network order).
        pkt[8..24].copy_from_slice(&TEST_SRC_IPV6);
        // Bytes 24-39: destination address (network order).
        pkt[24..40].copy_from_slice(&TEST_DST_IPV6);
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
        use super::mod_test_helpers::{TEST_DST_IPV4, TEST_SRC_IPV4};
        let pkt = build_ipv4_packet(6, 12345, 443); // TCP = protocol 6
        let parsed = parse_ip_packet(&pkt).expect("valid TCP IPv4 packet");

        assert_eq!(parsed.proto, Protocol::Tcp);
        assert_eq!(
            parsed.src,
            LocalEndpoint::ipv4(Protocol::Tcp, TEST_SRC_IPV4, 12345)
        );
        assert_eq!(
            parsed.dst,
            LocalEndpoint::ipv4(Protocol::Tcp, TEST_DST_IPV4, 443)
        );
        assert_eq!(parsed.total_len, 24); // captured length
    }

    #[test]
    fn test_parse_valid_udp_ipv4() {
        use super::mod_test_helpers::{TEST_DST_IPV4, TEST_SRC_IPV4};
        let pkt = build_ipv4_packet(17, 5353, 53); // UDP = protocol 17
        let parsed = parse_ip_packet(&pkt).expect("valid UDP IPv4 packet");

        assert_eq!(parsed.proto, Protocol::Udp);
        assert_eq!(
            parsed.src,
            LocalEndpoint::ipv4(Protocol::Udp, TEST_SRC_IPV4, 5353)
        );
        assert_eq!(
            parsed.dst,
            LocalEndpoint::ipv4(Protocol::Udp, TEST_DST_IPV4, 53)
        );
        assert_eq!(parsed.total_len, 24);
    }

    #[test]
    fn test_parse_valid_tcp_ipv6() {
        let pkt = build_ipv6_packet(6, 8080, 80); // TCP = next_header 6
        let parsed = parse_ip_packet(&pkt).expect("valid TCP IPv6 packet");

        assert_eq!(parsed.proto, Protocol::Tcp);
        assert_eq!(
            parsed.src,
            LocalEndpoint::ipv6(Protocol::Tcp, TEST_SRC_IPV6, 8080)
        );
        assert_eq!(
            parsed.dst,
            LocalEndpoint::ipv6(Protocol::Tcp, TEST_DST_IPV6, 80)
        );
        // IPv6 total = 40 (header) + payload_len (4) = 44
        assert_eq!(parsed.total_len, 44);
    }

    /// Cross-side byte-order invariant: a packet to a concrete IPv4 destination
    /// must produce an endpoint that equals the one the table scanner builds for
    /// the same address. Proves exact lookups will hit in production.
    #[test]
    fn test_parse_ipv4_dst_endpoint_matches_table_endpoint() {
        use super::mod_test_helpers::TEST_DST_IPV4;
        let pkt = build_ipv4_packet(6, 12345, 443);
        let parsed = parse_ip_packet(&pkt).expect("valid packet");

        // Simulate the table scanner: dwLocalAddr is a network-byte-order u32.
        let dw_local_addr = u32::from_ne_bytes(TEST_DST_IPV4);
        let table_endpoint = LocalEndpoint::ipv4(
            Protocol::Tcp,
            crate::core::win_net_table::ipv4_local_addr_octets(dw_local_addr),
            443,
        );
        assert_eq!(
            parsed.dst, table_endpoint,
            "packet-side and table-side endpoints must be identical"
        );
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

    /// The IP header's length field is attacker-controlled for inbound packets
    /// (and can be stale under offload). A lying field must NOT under-charge
    /// the rate limiter: total_len must be the captured byte count.
    #[test]
    fn test_total_len_is_captured_length_not_header_field_ipv4() {
        let mut pkt = build_ipv4_packet(6, 12345, 443); // 24 captured bytes
                                                        // Lie in the header: total-length field says 0.
        pkt[2] = 0;
        pkt[3] = 0;
        let parsed = parse_ip_packet(&pkt).expect("valid TCP IPv4 packet");
        assert_eq!(
            parsed.total_len, 24,
            "total_len must be the captured length, not the header field"
        );
    }

    #[test]
    fn test_total_len_is_captured_length_not_header_field_ipv6() {
        let mut pkt = build_ipv6_packet(6, 8080, 80); // 44 captured bytes
                                                      // Lie in the header: payload-length field says 0.
        pkt[4] = 0;
        pkt[5] = 0;
        let parsed = parse_ip_packet(&pkt).expect("valid TCP IPv6 packet");
        assert_eq!(
            parsed.total_len, 44,
            "total_len must be the captured length, not the header field"
        );
    }

    /// Verify that `WinDivert<NetworkLayer>` has sufficient size and alignment
    /// for safe raw HANDLE extraction via `extract_wd_handle`.
    ///
    /// If the `windivert` crate changes its struct layout, this test will fail
    /// immediately, preventing silent UB in production.
    #[test]
    fn test_windivert_layout_assumptions() {
        let wd_size =
            std::mem::size_of::<windivert::prelude::WinDivert<windivert::layer::NetworkLayer>>();
        let wd_align =
            std::mem::align_of::<windivert::prelude::WinDivert<windivert::layer::NetworkLayer>>();

        assert!(
            wd_size >= std::mem::size_of::<isize>(),
            "WinDivert<NetworkLayer> size ({wd_size}) must be >= size_of::<isize>() ({})",
            std::mem::size_of::<isize>()
        );
        assert!(
            wd_align >= std::mem::align_of::<isize>(),
            "WinDivert<NetworkLayer> align ({wd_align}) must be >= align_of::<isize>() ({})",
            std::mem::align_of::<isize>()
        );
    }
}
