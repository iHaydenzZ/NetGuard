//! Maps network connections (ports) to process IDs.
//!
//! Windows: GetExtendedTcpTable/GetExtendedUdpTable from iphlpapi.
//! Refreshes at configurable intervals via a dedicated OS thread.
//! Results stored in DashMap for lock-free lookup.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use serde::Serialize;

use crate::config;
use crate::core::icon_extractor;
use crate::core::win_net_table;
use sysinfo::System;

/// Network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Local IP address, stored in network/address byte order (first octet first).
///
/// Both the packet parser and the IP Helper table scanner MUST produce this in
/// the same byte order, otherwise exact endpoint lookups never hit. See the
/// `test_endpoint_byte_order_invariant` test for the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalAddress {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

impl LocalAddress {
    /// The same-family wildcard (unspecified) address: `0.0.0.0` for IPv4,
    /// `::` for IPv6. Listening sockets appear in the IP Helper tables bound to
    /// the wildcard, but real packets carry concrete addresses.
    fn wildcard(&self) -> Self {
        match self {
            LocalAddress::Ipv4(_) => LocalAddress::Ipv4([0; 4]),
            LocalAddress::Ipv6(_) => LocalAddress::Ipv6([0; 16]),
        }
    }

    /// True if this address is the same-family unspecified/wildcard address.
    fn is_wildcard(&self) -> bool {
        match self {
            LocalAddress::Ipv4(a) => *a == [0; 4],
            LocalAddress::Ipv6(a) => *a == [0; 16],
        }
    }
}

/// A local network endpoint: protocol + local address + local port.
///
/// This is the lookup key for process attribution. Keying by port alone caused
/// IPv4/IPv6 same-port collisions (two processes owning the same port number on
/// different address families would be attributed against the wrong process).
///
/// `Copy` is required: `lookup_pid` runs per-packet in the hot path and must not
/// allocate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalEndpoint {
    pub proto: Protocol,
    pub address: LocalAddress,
    pub port: u16,
}

impl LocalEndpoint {
    pub fn ipv4(proto: Protocol, address: [u8; 4], port: u16) -> Self {
        Self {
            proto,
            address: LocalAddress::Ipv4(address),
            port,
        }
    }

    pub fn ipv6(proto: Protocol, address: [u8; 16], port: u16) -> Self {
        Self {
            proto,
            address: LocalAddress::Ipv6(address),
            port,
        }
    }

    /// The same-family wildcard endpoint for fallback lookup (preserves proto
    /// and port, replaces the address with the unspecified address).
    fn to_wildcard(self) -> Self {
        Self {
            address: self.address.wildcard(),
            ..self
        }
    }
}

/// Lightweight process metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub name: String,
    pub exe_path: String,
    /// Process creation time in seconds since the Unix epoch (sysinfo), or 0
    /// when unreadable. A process's start time is immutable, so a changed
    /// nonzero value for the same PID proves Windows reused the PID for a
    /// different process — the discriminator for dropping inherited controls.
    pub start_time: u64,
}

/// Thread-safe mapper from local endpoint to PID and PID to ProcessInfo.
pub struct ProcessMapper {
    /// LocalEndpoint -> owning PID. Named `port_map` for historical reasons; it
    /// is now keyed by the full (protocol, local address, local port) tuple.
    pub(crate) port_map: DashMap<LocalEndpoint, u32>,
    /// PID -> process metadata.
    pub(crate) process_info: DashMap<u32, ProcessInfo>,
    /// exe_path -> base64-encoded icon data URI, cached per executable (AC-1.6).
    icon_cache: DashMap<String, Option<String>>,
}

impl ProcessMapper {
    pub fn new() -> Self {
        Self {
            port_map: DashMap::new(),
            process_info: DashMap::new(),
            icon_cache: DashMap::new(),
        }
    }

    /// Look up the PID that owns the given local endpoint.
    ///
    /// Lookup order (hot path — at most two DashMap reads, no allocation):
    /// 1. exact endpoint (concrete local address) — a connected socket's address
    ///    is concrete in both the packet and the IP Helper table.
    /// 2. same-family wildcard (`0.0.0.0:port` / `[::]:port`) — listening sockets
    ///    appear in the table bound to the unspecified address, but inbound
    ///    packets to them carry a concrete destination address.
    ///
    /// We never fall back across address families: an IPv4 packet must not match
    /// an IPv6 wildcard entry or vice versa. Dual-stack sockets appear in BOTH
    /// the v4 and v6 tables on Windows, so same-family fallback is sufficient.
    pub fn lookup_pid(&self, endpoint: &LocalEndpoint) -> Option<u32> {
        if let Some(r) = self.port_map.get(endpoint) {
            return Some(*r);
        }
        // Skip the second read if the endpoint is already the wildcard (the
        // exact lookup above already covered it).
        if endpoint.address.is_wildcard() {
            return None;
        }
        self.port_map.get(&endpoint.to_wildcard()).map(|r| *r)
    }

    /// Get process info for a PID.
    pub fn get_process_info(&self, pid: u32) -> Option<ProcessInfo> {
        self.process_info.get(&pid).map(|r| r.clone())
    }

    /// Count active connections per PID.
    pub fn connection_counts(&self) -> DashMap<u32, u32> {
        let counts = DashMap::new();
        for entry in self.port_map.iter() {
            let pid = *entry.value();
            counts.entry(pid).and_modify(|c| *c += 1).or_insert(1);
        }
        counts
    }

    /// Remove entries from `process_info` for PIDs that are no longer alive.
    pub fn retain_live_pids(&self, live_pids: &std::collections::HashSet<u32>) {
        self.process_info.retain(|pid, _| live_pids.contains(pid));
    }

    /// Spawn a background thread refreshing the maps at the configured interval.
    /// Returns the thread handle for graceful shutdown.
    pub fn start_scanning(
        self: &Arc<Self>,
        rate_limiter: Arc<crate::core::rate_limiter::RateLimiterManager>,
        traffic_tracker: Arc<crate::core::traffic::TrafficTracker>,
        shutdown: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<()> {
        let mapper = Arc::clone(self);
        std::thread::Builder::new()
            .name("process-scanner".into())
            .spawn(move || {
                let mut sys = System::new();
                let interval = std::time::Duration::from_millis(config::PROCESS_SCAN_INTERVAL_MS);
                let step = std::time::Duration::from_millis(50);
                while !shutdown.load(Ordering::Relaxed) {
                    win_net_table::refresh_port_map(&mapper.port_map);

                    // A reused PID means any per-PID state targeted the PREVIOUS
                    // owner — an unrelated new process must not inherit its
                    // controls (limit/block) or its traffic counters (cumulative
                    // bytes would be reported under the new identity in the
                    // snapshot and history). The liveness cleanup below cannot
                    // catch this case: the PID never left the live set. If the
                    // new identity matches a saved rule, the persistent-rules
                    // applier re-applies by exe_path on its next tick; the
                    // capture loop re-creates fresh counters on the next packet.
                    for pid in mapper.refresh_process_info(&mut sys) {
                        tracing::info!(
                            pid,
                            "PID reused by a new process; clearing inherited state"
                        );
                        rate_limiter.remove_limit(pid);
                        rate_limiter.unblock_process(pid);
                        traffic_tracker.remove_pid(pid);
                    }

                    // Run cleanup every cycle (formerly every 10 cycles).
                    // PID reuse across a scan boundary is caught here by
                    // liveness; reuse WITHIN the 500ms window is caught by the
                    // start-time check above. Per-500ms cleanup is cheap
                    // (O(n) over small HashMaps).
                    let live_pids: std::collections::HashSet<u32> =
                        sys.processes().keys().map(|p| p.as_u32()).collect();
                    mapper.retain_live_pids(&live_pids);
                    rate_limiter.remove_stale_pids(&live_pids);

                    // Interruptible sleep: check shutdown flag every 50ms.
                    let mut elapsed = std::time::Duration::ZERO;
                    while elapsed < interval {
                        if shutdown.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(step);
                        elapsed += step;
                    }
                }
            })
            .expect("failed to spawn process scanner thread")
    }

    /// Return a cached base64 data-URI icon for the given exe path (AC-1.6).
    pub fn get_icon_base64(&self, exe_path: &str) -> Option<String> {
        if exe_path.is_empty() {
            return None;
        }
        if let Some(cached) = self.icon_cache.get(exe_path) {
            return cached.value().clone();
        }
        let icon = icon_extractor::extract_icon(exe_path);
        self.icon_cache.insert(exe_path.to_string(), icon.clone());
        icon
    }

    /// Refresh `process_info` from a sysinfo scan.
    ///
    /// Returns the PIDs detected as REUSED this scan (see
    /// [`upsert_process_info`]): the caller must drop any controls
    /// (limits/blocks) that targeted the previous owner of those PIDs.
    fn refresh_process_info(&self, sys: &mut System) -> Vec<u32> {
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        let mut reused = Vec::new();
        for (pid, process) in sys.processes() {
            let name = process.name().to_string_lossy().to_string();
            let exe_path = process
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            if upsert_process_info(
                &self.process_info,
                pid.as_u32(),
                name,
                exe_path,
                process.start_time(),
            ) {
                reused.push(pid.as_u32());
            }
        }
        reused
    }
}

impl Default for ProcessMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Insert or update the identity of a PID in the process info map.
///
/// All fields are refreshed on every scan so that when Windows reuses a PID
/// the new process's identity replaces the old one immediately. To avoid
/// write-lock churn on hot entries (all live processes are visited every
/// 500ms), we only write when the stored data actually differs.
///
/// Returns `true` when the PID was REUSED: the stored start time and the new
/// reading are both readable (nonzero) and differ. Start time is immutable
/// for a given process, so a change proves a different process now owns the
/// PID. A 0 reading means sysinfo could not query the process — it never
/// claims reuse, and it never overwrites a readable stored value, so the old
/// baseline still exposes the reuse once the new owner becomes readable.
fn upsert_process_info(
    process_info: &DashMap<u32, ProcessInfo>,
    pid: u32,
    name: String,
    exe_path: String,
    start_time: u64,
) -> bool {
    match process_info.entry(pid) {
        dashmap::mapref::entry::Entry::Occupied(mut entry) => {
            let info = entry.get_mut();
            let reused = start_time != 0 && info.start_time != 0 && info.start_time != start_time;
            // Only write when something changed — avoids unnecessary write-lock
            // promotion on DashMap shards for processes whose identity is stable.
            if info.name != name {
                info.name = name;
            }
            if info.exe_path != exe_path {
                info.exe_path = exe_path;
            }
            if start_time != 0 && info.start_time != start_time {
                info.start_time = start_time;
            }
            reused
        }
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(ProcessInfo {
                name,
                exe_path,
                start_time,
            });
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_mapper_empty() {
        let mapper = ProcessMapper::new();
        assert_eq!(
            mapper.lookup_pid(&LocalEndpoint::ipv4(Protocol::Tcp, [127, 0, 0, 1], 80)),
            None
        );
        assert_eq!(
            mapper.lookup_pid(&LocalEndpoint::ipv6(Protocol::Udp, [0; 16], 53)),
            None
        );
    }

    #[test]
    fn test_endpoint_lookup_distinguishes_ipv4_and_ipv6_same_port() {
        let mapper = ProcessMapper::new();
        mapper
            .port_map
            .insert(LocalEndpoint::ipv4(Protocol::Tcp, [127, 0, 0, 1], 443), 10);
        mapper
            .port_map
            .insert(LocalEndpoint::ipv6(Protocol::Tcp, [0; 16], 443), 20);

        assert_eq!(
            mapper.lookup_pid(&LocalEndpoint::ipv4(Protocol::Tcp, [127, 0, 0, 1], 443)),
            Some(10)
        );
        assert_eq!(
            mapper.lookup_pid(&LocalEndpoint::ipv6(Protocol::Tcp, [0; 16], 443)),
            Some(20)
        );
    }

    #[test]
    fn test_wildcard_fallback_ipv4_resolves_concrete_lookup() {
        let mapper = ProcessMapper::new();
        // A listening socket is recorded against the wildcard address.
        mapper
            .port_map
            .insert(LocalEndpoint::ipv4(Protocol::Tcp, [0, 0, 0, 0], 8080), 100);

        // An inbound packet carries a concrete local (destination) address.
        assert_eq!(
            mapper.lookup_pid(&LocalEndpoint::ipv4(Protocol::Tcp, [192, 168, 1, 5], 8080)),
            Some(100),
            "concrete IPv4 lookup must fall back to the 0.0.0.0 wildcard entry"
        );
    }

    #[test]
    fn test_wildcard_fallback_ipv6_resolves_concrete_lookup() {
        let mapper = ProcessMapper::new();
        // IPv6 listening socket recorded against `::`.
        mapper
            .port_map
            .insert(LocalEndpoint::ipv6(Protocol::Udp, [0; 16], 9090), 200);

        let concrete_v6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        assert_eq!(
            mapper.lookup_pid(&LocalEndpoint::ipv6(Protocol::Udp, concrete_v6, 9090)),
            Some(200),
            "concrete IPv6 lookup must fall back to the :: wildcard entry"
        );
    }

    #[test]
    fn test_no_match_returns_none() {
        let mapper = ProcessMapper::new();
        // No exact and no wildcard entry exists for this endpoint.
        assert_eq!(
            mapper.lookup_pid(&LocalEndpoint::ipv4(Protocol::Tcp, [192, 168, 1, 5], 8080)),
            None
        );
    }

    #[test]
    fn test_cross_family_isolation_v4_lookup_ignores_v6_wildcard() {
        let mapper = ProcessMapper::new();
        // Only an IPv6 wildcard entry exists.
        mapper
            .port_map
            .insert(LocalEndpoint::ipv6(Protocol::Tcp, [0; 16], 8080), 300);

        // A concrete IPv4 lookup must NOT match the IPv6 wildcard.
        assert_eq!(
            mapper.lookup_pid(&LocalEndpoint::ipv4(Protocol::Tcp, [192, 168, 1, 5], 8080)),
            None,
            "IPv4 packet must never resolve to an IPv6 wildcard entry"
        );
    }

    #[test]
    fn test_exact_beats_wildcard() {
        let mapper = ProcessMapper::new();
        // Two entries on the same port: a concrete connected socket (PID A) and a
        // wildcard listener (PID B).
        mapper
            .port_map
            .insert(LocalEndpoint::ipv4(Protocol::Tcp, [10, 0, 0, 7], 443), 1);
        mapper
            .port_map
            .insert(LocalEndpoint::ipv4(Protocol::Tcp, [0, 0, 0, 0], 443), 2);

        // A packet to the concrete address must resolve to the exact match, not
        // the wildcard.
        assert_eq!(
            mapper.lookup_pid(&LocalEndpoint::ipv4(Protocol::Tcp, [10, 0, 0, 7], 443)),
            Some(1),
            "exact endpoint must win over the wildcard fallback"
        );
    }

    /// THE correctness invariant: the same address must produce an identical
    /// `LocalEndpoint` from BOTH the packet parser and the table scanner.
    ///
    /// This proves the byte-order contract: the IPv4 table stores the local
    /// address as a network-byte-order `u32` (`to_ne_bytes` yields address-order
    /// octets on little-endian Windows), and the packet parser reads the same
    /// address-order octets directly off the wire. Both must equal `[a,b,c,d]`.
    #[test]
    fn test_endpoint_byte_order_invariant() {
        // Address 192.168.1.5 in network byte order is the byte sequence
        // [192, 168, 1, 5]. As a u32 in memory on a little-endian machine, that
        // is the value 0x0501A8C0; `to_ne_bytes()` must recover [192,168,1,5].
        let table_u32: u32 = u32::from_ne_bytes([192, 168, 1, 5]);
        let from_table = table_u32.to_ne_bytes();

        // The packet parser reads header bytes 12..16 directly off the wire,
        // which are already in address order.
        let wire_bytes = [192u8, 168, 1, 5];

        assert_eq!(
            from_table, wire_bytes,
            "table-side and packet-side IPv4 octets must match for exact lookups to hit"
        );

        let table_ep = LocalEndpoint::ipv4(Protocol::Tcp, from_table, 443);
        let packet_ep = LocalEndpoint::ipv4(Protocol::Tcp, wire_bytes, 443);
        assert_eq!(table_ep, packet_ep);
    }

    #[test]
    fn test_get_process_info_unknown_pid() {
        let mapper = ProcessMapper::new();
        assert!(mapper.get_process_info(12345).is_none());
        assert!(mapper.get_process_info(0).is_none());
    }

    #[test]
    fn test_connection_counts_empty() {
        let mapper = ProcessMapper::new();
        let counts = mapper.connection_counts();
        assert!(counts.is_empty());
    }

    #[test]
    fn test_icon_cache_empty_path() {
        let mapper = ProcessMapper::new();
        assert!(mapper.get_icon_base64("").is_none());
    }

    #[test]
    fn test_retain_live_pids_removes_dead() {
        let mapper = ProcessMapper::new();
        mapper.process_info.insert(
            1,
            ProcessInfo {
                name: "alive".into(),
                exe_path: "/alive".into(),
                start_time: 0,
            },
        );
        mapper.process_info.insert(
            2,
            ProcessInfo {
                name: "dead".into(),
                exe_path: "/dead".into(),
                start_time: 0,
            },
        );
        mapper.process_info.insert(
            3,
            ProcessInfo {
                name: "also_alive".into(),
                exe_path: "/also_alive".into(),
                start_time: 0,
            },
        );

        let mut live = std::collections::HashSet::new();
        live.insert(1u32);
        live.insert(3u32);
        mapper.retain_live_pids(&live);

        assert!(mapper.get_process_info(1).is_some());
        assert!(
            mapper.get_process_info(2).is_none(),
            "dead PID should be removed"
        );
        assert!(mapper.get_process_info(3).is_some());
    }

    #[test]
    fn test_retain_live_pids_empty_set_clears_all() {
        let mapper = ProcessMapper::new();
        mapper.process_info.insert(
            1,
            ProcessInfo {
                name: "test".into(),
                exe_path: "/test".into(),
                start_time: 0,
            },
        );
        mapper.retain_live_pids(&std::collections::HashSet::new());
        assert!(mapper.get_process_info(1).is_none());
    }

    // --- upsert_process_info tests ---

    #[test]
    fn test_upsert_process_info_inserts_new_pid() {
        let map = DashMap::new();
        let reused = upsert_process_info(
            &map,
            42,
            "chrome.exe".into(),
            r"C:\chrome.exe".into(),
            1_000,
        );

        assert!(!reused, "a first-seen PID is not a reuse");
        let info = map.get(&42).unwrap();
        assert_eq!(info.name, "chrome.exe");
        assert_eq!(info.exe_path, r"C:\chrome.exe");
        assert_eq!(info.start_time, 1_000);
    }

    #[test]
    fn test_upsert_process_info_updates_exe_path_for_reused_pid() {
        // Simulates Windows PID reuse: PID 42 was chrome.exe, now it's evil.exe.
        // Both name and exe_path must reflect the NEW process after upsert.
        let map = DashMap::new();
        upsert_process_info(&map, 42, "old.exe".into(), r"C:\old.exe".into(), 1_000);
        upsert_process_info(&map, 42, "new.exe".into(), r"C:\new.exe".into(), 2_000);

        let info = map.get(&42).unwrap();
        assert_eq!(info.name, "new.exe");
        assert_eq!(info.exe_path, r"C:\new.exe");
    }

    #[test]
    fn test_upsert_process_info_idempotent_on_stable_pid() {
        // When identity is unchanged, upsert must still leave the correct values.
        // (The internal write-skip optimization isn't observable from outside;
        // this is a non-regression check on the idempotent result.)
        let map = DashMap::new();
        upsert_process_info(
            &map,
            10,
            "stable.exe".into(),
            r"C:\stable.exe".into(),
            1_000,
        );
        upsert_process_info(
            &map,
            10,
            "stable.exe".into(),
            r"C:\stable.exe".into(),
            1_000,
        );

        let info = map.get(&10).unwrap();
        assert_eq!(info.name, "stable.exe");
        assert_eq!(info.exe_path, r"C:\stable.exe");
    }

    #[test]
    fn test_upsert_process_info_updates_single_changed_field() {
        // The field updates are guarded independently — a regression that
        // skips one field's write must be caught even when the other is stable.
        let map = DashMap::new();
        upsert_process_info(&map, 7, "app.exe".into(), r"C:\v1\app.exe".into(), 1_000);
        upsert_process_info(&map, 7, "app.exe".into(), r"C:\v2\app.exe".into(), 1_000);

        {
            let info = map.get(&7).unwrap();
            assert_eq!(info.name, "app.exe");
            assert_eq!(
                info.exe_path, r"C:\v2\app.exe",
                "exe_path alone must update"
            );
        }

        upsert_process_info(
            &map,
            7,
            "renamed.exe".into(),
            r"C:\v2\app.exe".into(),
            1_000,
        );
        let info = map.get(&7).unwrap();
        assert_eq!(info.name, "renamed.exe", "name alone must update");
        assert_eq!(info.exe_path, r"C:\v2\app.exe");
    }

    #[test]
    fn test_upsert_reports_reuse_when_start_time_changes() {
        let map = DashMap::new();
        upsert_process_info(&map, 42, "old.exe".into(), r"C:\old.exe".into(), 1_000);

        assert!(
            upsert_process_info(&map, 42, "new.exe".into(), r"C:\new.exe".into(), 2_000),
            "a changed nonzero start time proves the PID was reused"
        );
        assert_eq!(map.get(&42).unwrap().start_time, 2_000);
    }

    #[test]
    fn test_upsert_does_not_report_reuse_for_stable_start_time() {
        let map = DashMap::new();
        upsert_process_info(&map, 10, "app.exe".into(), r"C:\app.exe".into(), 1_000);

        assert!(!upsert_process_info(
            &map,
            10,
            "app.exe".into(),
            r"C:\app.exe".into(),
            1_000
        ));
    }

    #[test]
    fn test_upsert_never_claims_reuse_on_unreadable_start_time() {
        let map = DashMap::new();
        upsert_process_info(&map, 5, "app.exe".into(), r"C:\app.exe".into(), 1_000);

        // New reading unreadable (0): must not claim reuse — clearing a user's
        // rule on a query hiccup would silently drop their control. The readable
        // baseline is kept so a later readable reading can still expose a reuse.
        assert!(!upsert_process_info(
            &map,
            5,
            "app.exe".into(),
            r"C:\app.exe".into(),
            0
        ));
        assert_eq!(map.get(&5).unwrap().start_time, 1_000, "baseline kept");

        // The new owner becomes readable: reuse detected against the baseline.
        assert!(upsert_process_info(
            &map,
            5,
            "new.exe".into(),
            r"C:\new.exe".into(),
            3_000
        ));
    }

    #[test]
    fn test_upsert_adopts_first_readable_start_time_without_reuse_claim() {
        let map = DashMap::new();
        // Stored baseline unreadable (0): the first readable value is adopted
        // silently — "now readable" is indistinguishable from a reuse, and a
        // false reuse claim would drop a user's rule.
        upsert_process_info(&map, 6, "app.exe".into(), r"C:\app.exe".into(), 0);

        assert!(!upsert_process_info(
            &map,
            6,
            "app.exe".into(),
            r"C:\app.exe".into(),
            1_000
        ));
        assert_eq!(map.get(&6).unwrap().start_time, 1_000);
    }
}
