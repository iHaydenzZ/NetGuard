//! Windows IP Helper FFI for querying TCP/UDP port-to-PID tables.
//!
//! Wraps `GetExtendedTcpTable` / `GetExtendedUdpTable` from `iphlpapi.dll`
//! for both IPv4 and IPv6.

use dashmap::DashMap;

use crate::core::process_mapper::{LocalEndpoint, Protocol};

pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 23;
pub const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
pub const UDP_TABLE_OWNER_PID: u32 = 1;
pub const NO_ERROR: u32 = 0;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// Maximum buffer size for IP helper table queries (16 MB).
/// Prevents unbounded allocation from a corrupted API return value.
const MAX_TABLE_BUFFER: usize = 16 * 1024 * 1024;

// --- IPv4 row structures ---

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MibTcpRowOwnerPid {
    pub state: u32,
    pub local_addr: u32,
    pub local_port: u32,
    pub remote_addr: u32,
    pub remote_port: u32,
    pub owning_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MibUdpRowOwnerPid {
    pub local_addr: u32,
    pub local_port: u32,
    pub owning_pid: u32,
}

// --- IPv6 row structures ---

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MibTcp6RowOwnerPid {
    pub local_addr: [u8; 16],
    pub local_scope_id: u32,
    pub local_port: u32,
    pub remote_addr: [u8; 16],
    pub remote_scope_id: u32,
    pub remote_port: u32,
    pub state: u32,
    pub owning_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MibUdp6RowOwnerPid {
    pub local_addr: [u8; 16],
    pub local_scope_id: u32,
    pub local_port: u32,
    pub owning_pid: u32,
}

#[link(name = "iphlpapi")]
extern "system" {
    pub fn GetExtendedTcpTable(
        pTcpTable: *mut u8,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;

    pub fn GetExtendedUdpTable(
        pUdpTable: *mut u8,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;
}

/// Convert an IPv4 `dwLocalAddr` field into address-order octets.
///
/// `dwLocalAddr` is documented as network byte order. On little-endian Windows
/// the in-memory byte layout of that `u32` is already `[octet0, octet1, octet2,
/// octet3]`, so `to_ne_bytes()` recovers the address-order octets — matching the
/// octets the packet parser reads directly off the wire (IPv4 header bytes
/// 12..16). This equality is the exact-lookup correctness invariant.
#[inline]
pub(crate) fn ipv4_local_addr_octets(local_addr: u32) -> [u8; 4] {
    local_addr.to_ne_bytes()
}

/// Type of the IP Helper table-fetch FFI (`GetExtendedTcpTable` /
/// `GetExtendedUdpTable` share this signature).
type TableFn = unsafe extern "system" fn(*mut u8, *mut u32, i32, u32, u32, u32) -> u32;

/// Static description of one IP Helper table to scan: which FFI to call, the
/// address family / table class to request, the protocol the rows represent, and
/// a log label. Bundled so the scan/fetch helpers stay under the argument limit.
struct TableQuery {
    ffi_fn: TableFn,
    af: u32,
    table_class: u32,
    proto: Protocol,
    label: &'static str,
}

/// Parse an IP Helper `MIB_*_TABLE_OWNER_PID` byte buffer into owned rows.
///
/// Layout of these tables: a `DWORD dwNumEntries` followed by the row array.
/// On x86/x64 the row structs here (all start with a 4-byte field) need no
/// padding after the count, so the first row begins at offset 4 — matching the
/// arithmetic the old scan loop used.
///
/// Rows are read with `std::ptr::read_unaligned` into owned `T` values: the
/// buffer comes from a `Vec<u8>` whose alignment makes no guarantee for `T`, so
/// forming `&T` references into it would be undefined behavior.
///
/// `dwNumEntries` is never trusted blindly — it is clamped to the number of
/// whole rows the buffer can actually hold, so a corrupted count cannot drive an
/// out-of-bounds read.
fn parse_table_rows<T: Copy>(buf: &[u8]) -> Vec<T> {
    const HEADER: usize = 4; // dwNumEntries: DWORD
    if buf.len() < HEADER {
        return Vec::new();
    }
    let row_size = std::mem::size_of::<T>();
    if row_size == 0 {
        return Vec::new();
    }
    let declared = u32::from_ne_bytes(buf[0..HEADER].try_into().unwrap()) as usize;
    let capacity = (buf.len() - HEADER) / row_size;
    let count = declared.min(capacity);

    let mut rows = Vec::with_capacity(count);
    for i in 0..count {
        let offset = HEADER + i * row_size;
        // SAFETY: `offset` is bounded by `capacity` above so
        // `offset + row_size <= buf.len()`, and `read_unaligned` tolerates the
        // buffer's arbitrary alignment.
        let row = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const T) };
        rows.push(row);
    }
    rows
}

/// Extract the local port from an OWNER_PID row's `local_port` field.
///
/// All four row types store the port in the low 16 bits of a `DWORD` in network
/// byte order, so the same conversion applies uniformly. Windows zero-extends
/// the u16 port into the DWORD, so the high 16 bits are always zero and the
/// `as u16` truncation is intentional, not lossy.
#[inline]
fn local_port_from_field(local_port: u32) -> u16 {
    u16::from_be(local_port as u16)
}

/// Fetch one IP Helper table into a byte buffer.
///
/// Returns `None` on failure (logged) so the caller can preserve the previous
/// map instead of publishing a partial one. If the fetch reports
/// `ERROR_INSUFFICIENT_BUFFER` the whole sequence (size-query, allocation, fetch)
/// is retried once: the table can grow between the sizing call and the fetch, and
/// a single retry covers that.
fn fetch_table(query: &TableQuery) -> Option<Vec<u8>> {
    // `proto` is deliberately unused: fetching is protocol-agnostic; only the
    // endpoint construction in `scan_table` needs it.
    let TableQuery {
        ffi_fn,
        af,
        table_class,
        label,
        proto: _,
    } = *query;
    for attempt in 0..2 {
        let mut size: u32 = 0;
        let ret = unsafe { ffi_fn(std::ptr::null_mut(), &mut size, 0, af, table_class, 0) };
        if ret != ERROR_INSUFFICIENT_BUFFER {
            tracing::warn!("{label} size query returned {ret}");
            return None;
        }

        let alloc_size = size as usize;
        if alloc_size > MAX_TABLE_BUFFER {
            tracing::warn!("{label} requested {alloc_size} bytes, exceeds cap");
            return None;
        }
        let mut buf = vec![0u8; alloc_size];
        let ret = unsafe { ffi_fn(buf.as_mut_ptr(), &mut size, 0, af, table_class, 0) };
        match ret {
            NO_ERROR => return Some(buf),
            ERROR_INSUFFICIENT_BUFFER if attempt == 0 => {
                // Table grew between sizing and fetch; retry once with a fresh size.
                tracing::debug!("{label} grew between size query and fetch, retrying");
                continue;
            }
            _ => {
                tracing::warn!("{label} fetch failed with code {ret}");
                return None;
            }
        }
    }
    None
}

/// Scan one IP Helper table into `next_map`.
///
/// `local_port` / `owning_pid` pull those fields out of the concrete (and now
/// owned, post-`read_unaligned`) row type; `make_endpoint` builds the lookup key
/// from the row's address field, protocol and parsed port.
///
/// Returns `false` if the table could not be fetched, signalling the caller to
/// abandon this refresh cycle and keep the previous (complete) map.
fn scan_table<T: Copy>(
    next_map: &mut std::collections::HashMap<LocalEndpoint, u32>,
    query: &TableQuery,
    local_port: fn(&T) -> u16,
    owning_pid: fn(&T) -> u32,
    make_endpoint: fn(&T, Protocol, u16) -> LocalEndpoint,
) -> bool {
    let buf = match fetch_table(query) {
        Some(buf) => buf,
        None => return false,
    };
    for row in parse_table_rows::<T>(&buf) {
        let port = local_port(&row);
        let pid = owning_pid(&row);
        if port > 0 && pid > 0 {
            next_map.insert(make_endpoint(&row, query.proto, port), pid);
        }
    }
    true
}

/// Scan all TCP and UDP tables (IPv4 + IPv6) and publish the result.
///
/// Failure semantics: each of the four tables is scanned into a temporary map
/// first; the live `port_map` is only cleared and repopulated once ALL four
/// scans succeed. If any single scan fails, later tables are not attempted and
/// the previous map is left untouched for this cycle. A stale-but-complete map
/// attributes traffic correctly across
/// all four address-family/protocol combinations; a fresh-but-partial map would
/// silently mis-attribute one whole family until the next 500ms tick. Holding
/// the previous map one extra cycle is the safer trade.
pub fn refresh_port_map(port_map: &DashMap<LocalEndpoint, u32>) {
    let mut next_map: std::collections::HashMap<LocalEndpoint, u32> =
        std::collections::HashMap::with_capacity(port_map.len());

    let ok = scan_table::<MibTcpRowOwnerPid>(
        &mut next_map,
        &TableQuery {
            ffi_fn: GetExtendedTcpTable,
            af: AF_INET,
            table_class: TCP_TABLE_OWNER_PID_ALL,
            proto: Protocol::Tcp,
            label: "GetExtendedTcpTable",
        },
        |row| local_port_from_field(row.local_port),
        |row| row.owning_pid,
        |row, proto, port| LocalEndpoint::ipv4(proto, ipv4_local_addr_octets(row.local_addr), port),
    ) && scan_table::<MibUdpRowOwnerPid>(
        &mut next_map,
        &TableQuery {
            ffi_fn: GetExtendedUdpTable,
            af: AF_INET,
            table_class: UDP_TABLE_OWNER_PID,
            proto: Protocol::Udp,
            label: "GetExtendedUdpTable",
        },
        |row| local_port_from_field(row.local_port),
        |row| row.owning_pid,
        |row, proto, port| LocalEndpoint::ipv4(proto, ipv4_local_addr_octets(row.local_addr), port),
    ) && scan_table::<MibTcp6RowOwnerPid>(
        &mut next_map,
        &TableQuery {
            ffi_fn: GetExtendedTcpTable,
            af: AF_INET6,
            table_class: TCP_TABLE_OWNER_PID_ALL,
            proto: Protocol::Tcp,
            label: "GetExtendedTcpTable(AF_INET6)",
        },
        |row| local_port_from_field(row.local_port),
        |row| row.owning_pid,
        |row, proto, port| LocalEndpoint::ipv6(proto, row.local_addr, port),
    ) && scan_table::<MibUdp6RowOwnerPid>(
        &mut next_map,
        &TableQuery {
            ffi_fn: GetExtendedUdpTable,
            af: AF_INET6,
            table_class: UDP_TABLE_OWNER_PID,
            proto: Protocol::Udp,
            label: "GetExtendedUdpTable(AF_INET6)",
        },
        |row| local_port_from_field(row.local_port),
        |row| row.owning_pid,
        |row, proto, port| LocalEndpoint::ipv6(proto, row.local_addr, port),
    );

    if !ok {
        // Keep the previous, complete map for this cycle.
        tracing::warn!("port map refresh aborted; retaining previous map");
        return;
    }

    port_map.clear();
    for (key, pid) in next_map {
        port_map.insert(key, pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `dwLocalAddr` (network byte order u32) must convert to address-order
    /// octets matching what the packet parser reads off the wire. If this drifts,
    /// every exact (concrete-address) lookup silently misses.
    #[test]
    fn test_ipv4_local_addr_octets_network_order() {
        // 192.168.1.5 on the wire is the byte sequence [192,168,1,5]. The IP
        // Helper API stores that in dwLocalAddr as a network-byte-order u32,
        // whose little-endian in-memory representation is 0x0501A8C0.
        let dw_local_addr = u32::from_ne_bytes([192, 168, 1, 5]);
        assert_eq!(ipv4_local_addr_octets(dw_local_addr), [192, 168, 1, 5]);
    }

    #[test]
    fn test_ipv4_local_addr_octets_wildcard() {
        // 0.0.0.0 must round-trip to the wildcard octets for fallback matching.
        assert_eq!(ipv4_local_addr_octets(0), [0, 0, 0, 0]);
    }

    /// Build a byte buffer in the IP Helper `MIB_*_TABLE_OWNER_PID` layout:
    /// a 4-byte little-endian count followed by the raw bytes of each row.
    fn build_udp_table(rows: &[MibUdpRowOwnerPid], declared: u32) -> Vec<u8> {
        let mut buf = declared.to_ne_bytes().to_vec();
        for row in rows {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    row as *const MibUdpRowOwnerPid as *const u8,
                    std::mem::size_of::<MibUdpRowOwnerPid>(),
                )
            };
            buf.extend_from_slice(bytes);
        }
        buf
    }

    /// Build a byte buffer for MibUdp6RowOwnerPid rows (IPv6 UDP table layout).
    fn build_udp6_table(rows: &[MibUdp6RowOwnerPid], declared: u32) -> Vec<u8> {
        let mut buf = declared.to_ne_bytes().to_vec();
        for row in rows {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    row as *const MibUdp6RowOwnerPid as *const u8,
                    std::mem::size_of::<MibUdp6RowOwnerPid>(),
                )
            };
            buf.extend_from_slice(bytes);
        }
        buf
    }

    /// The parser must read rows correctly even when the buffer's start address
    /// is not aligned for the row type — `read_unaligned` makes this sound where
    /// forming `&T` references into the buffer would be undefined behavior.
    #[test]
    fn test_parse_table_rows_handles_unaligned_buffer() {
        let row = MibUdpRowOwnerPid {
            local_addr: 0,
            // Port 53 stored low-16 network byte order, matching the real table.
            local_port: (53u16.to_be()) as u32,
            owning_pid: 123,
        };

        // Prepend one byte so `&buf[1..]` is deliberately misaligned for u32.
        let mut buf = vec![0xAA];
        buf.extend_from_slice(&build_udp_table(&[row], 1));

        let rows = parse_table_rows::<MibUdpRowOwnerPid>(&buf[1..]);
        assert_eq!(rows.len(), 1);
        assert_eq!(local_port_from_field(rows[0].local_port), 53);
        assert_eq!(rows[0].owning_pid, 123);
    }

    /// A corrupted/oversized `dwNumEntries` must never drive a read past the end
    /// of the buffer: the parser clamps to whole rows the buffer can hold.
    #[test]
    fn test_parse_table_rows_clamps_oversized_count() {
        let row = MibUdpRowOwnerPid {
            local_addr: 0,
            local_port: (80u16.to_be()) as u32,
            owning_pid: 7,
        };
        // One row present, but the header lies and claims 9999.
        let buf = build_udp_table(&[row], 9999);

        let rows = parse_table_rows::<MibUdpRowOwnerPid>(&buf);
        assert_eq!(rows.len(), 1, "count must be clamped to buffer capacity");
        assert_eq!(rows[0].owning_pid, 7);
    }

    #[test]
    fn test_parse_table_rows_empty_and_header_only() {
        // Too short to hold the count header at all.
        assert_eq!(parse_table_rows::<MibUdpRowOwnerPid>(&[]).len(), 0);
        assert_eq!(parse_table_rows::<MibUdpRowOwnerPid>(&[0, 0]).len(), 0);
        // Valid header declaring zero rows.
        let buf = build_udp_table(&[], 0);
        assert_eq!(parse_table_rows::<MibUdpRowOwnerPid>(&buf).len(), 0);
    }

    /// `local_port_from_field` must convert the DWORD's low-16-bit network-byte-order
    /// port back to host order for IPv4 rows.
    ///
    /// Port 8080 = 0x1F90 host order.  In network byte order the 16-bit value is
    /// 0x901F (bytes [0x90, 0x1F]).  The DWORD stores that in its low 16 bits, so
    /// the u32 value is 0x0000_901F.  `local_port_from_field` must recover 8080.
    #[test]
    fn test_ipv4_local_port_byte_order() {
        // Port 8080: network-byte-order u16 = 0x901F; zero-extended to u32 = 0x0000_901F.
        let dword = (8080u16.to_be()) as u32;
        assert_eq!(dword, 0x0000_901F, "pre-condition: DWORD encoding");
        assert_eq!(local_port_from_field(dword), 8080);

        // Port 443: network-byte-order u16 = 0x01BB; zero-extended to u32 = 0x0000_01BB.
        let dword_443 = (443u16.to_be()) as u32;
        assert_eq!(local_port_from_field(dword_443), 443);

        // Port 1 (edge): big-endian u16 = 0x0100; u32 = 0x0000_0100.
        let dword_1 = (1u16.to_be()) as u32;
        assert_eq!(local_port_from_field(dword_1), 1);

        // Port 65535 (edge): big-endian u16 = 0xFFFF; u32 = 0x0000_FFFF.
        let dword_max = (65535u16.to_be()) as u32;
        assert_eq!(local_port_from_field(dword_max), 65535);
    }

    /// Same `local_port_from_field` function applies to IPv6 rows (MibUdp6RowOwnerPid).
    /// Verify the byte-order conversion is correct when parsed through the v6 table path.
    #[test]
    fn test_ipv6_local_port_byte_order() {
        // Port 8080 stored in an IPv6 UDP row.
        let row = MibUdp6RowOwnerPid {
            local_addr: [0u8; 16],
            local_scope_id: 0,
            // Port 8080 in network byte order in the low 16 bits of the DWORD.
            local_port: (8080u16.to_be()) as u32,
            owning_pid: 42,
        };
        let buf = build_udp6_table(&[row], 1);
        let rows = parse_table_rows::<MibUdp6RowOwnerPid>(&buf);
        assert_eq!(rows.len(), 1);
        assert_eq!(local_port_from_field(rows[0].local_port), 8080);
        assert_eq!(rows[0].owning_pid, 42);

        // Port 443 in an IPv6 UDP row.
        let row_443 = MibUdp6RowOwnerPid {
            local_addr: [0u8; 16],
            local_scope_id: 0,
            local_port: (443u16.to_be()) as u32,
            owning_pid: 99,
        };
        let buf_443 = build_udp6_table(&[row_443], 1);
        let rows_443 = parse_table_rows::<MibUdp6RowOwnerPid>(&buf_443);
        assert_eq!(local_port_from_field(rows_443[0].local_port), 443);
    }

    /// Multiple rows in a buffer must be parsed in order with correct field values.
    #[test]
    fn test_parse_table_rows_multi_row_order() {
        let rows_in = [
            MibUdpRowOwnerPid {
                local_addr: 0,
                local_port: (80u16.to_be()) as u32,
                owning_pid: 1001,
            },
            MibUdpRowOwnerPid {
                local_addr: 0,
                local_port: (443u16.to_be()) as u32,
                owning_pid: 1002,
            },
            MibUdpRowOwnerPid {
                local_addr: 0,
                local_port: (8080u16.to_be()) as u32,
                owning_pid: 1003,
            },
        ];
        let buf = build_udp_table(&rows_in, 3);
        let parsed = parse_table_rows::<MibUdpRowOwnerPid>(&buf);

        assert_eq!(parsed.len(), 3);
        assert_eq!(local_port_from_field(parsed[0].local_port), 80);
        assert_eq!(parsed[0].owning_pid, 1001);
        assert_eq!(local_port_from_field(parsed[1].local_port), 443);
        assert_eq!(parsed[1].owning_pid, 1002);
        assert_eq!(local_port_from_field(parsed[2].local_port), 8080);
        assert_eq!(parsed[2].owning_pid, 1003);
    }
}
