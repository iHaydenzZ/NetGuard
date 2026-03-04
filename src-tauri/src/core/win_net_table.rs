//! Windows IP Helper FFI for querying TCP/UDP port-to-PID tables.
//!
//! Wraps `GetExtendedTcpTable` / `GetExtendedUdpTable` from `iphlpapi.dll`
//! for both IPv4 and IPv6.

use dashmap::DashMap;

use crate::core::process_mapper::Protocol;

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
pub struct MibTcpRowOwnerPid {
    pub state: u32,
    pub local_addr: u32,
    pub local_port: u32,
    pub remote_addr: u32,
    pub remote_port: u32,
    pub owning_pid: u32,
}

#[repr(C)]
pub struct MibUdpRowOwnerPid {
    pub local_addr: u32,
    pub local_port: u32,
    pub owning_pid: u32,
}

// --- IPv6 row structures ---

#[repr(C)]
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

/// Scans an IP helper table (TCP or UDP, IPv4 or IPv6) and inserts
/// `(protocol, local_port) → owning_pid` entries into `port_map`.
///
/// Parameterized over: FFI function, address family, table class, row type,
/// protocol variant, and a label for log messages.
macro_rules! scan_table {
    ($port_map:expr, $ffi_fn:ident, $af:expr, $table_class:expr, $row_ty:ty, $proto:expr, $label:expr) => {{
        let mut size: u32 = 0;
        let ret = unsafe { $ffi_fn(std::ptr::null_mut(), &mut size, 0, $af, $table_class, 0) };
        if ret != ERROR_INSUFFICIENT_BUFFER {
            return;
        }

        let alloc_size = size as usize;
        if alloc_size > MAX_TABLE_BUFFER {
            tracing::warn!("{} requested {alloc_size} bytes, exceeds cap", $label);
            return;
        }
        let mut buf = vec![0u8; alloc_size];
        let ret = unsafe { $ffi_fn(buf.as_mut_ptr(), &mut size, 0, $af, $table_class, 0) };
        if ret != NO_ERROR {
            tracing::warn!("{} failed with code {ret}", $label);
            return;
        }

        if buf.len() < 4 {
            return;
        }
        let row_size = std::mem::size_of::<$row_ty>();
        let raw_entries = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let num_entries = raw_entries.min(buf.len().saturating_sub(4) / row_size);

        for i in 0..num_entries {
            let offset = match 4_usize.checked_add(i.saturating_mul(row_size)) {
                Some(o) => o,
                None => break,
            };
            if offset.saturating_add(row_size) > buf.len() {
                break;
            }
            let row = unsafe { &*(buf.as_ptr().add(offset) as *const $row_ty) };
            let port = u16::from_be(row.local_port as u16);
            if port > 0 && row.owning_pid > 0 {
                $port_map.insert(($proto, port), row.owning_pid);
            }
        }
    }};
}

/// Scan all TCP and UDP tables (IPv4 + IPv6) and populate the port map.
pub fn refresh_port_map(port_map: &DashMap<(Protocol, u16), u32>) {
    port_map.clear();
    scan_table!(port_map, GetExtendedTcpTable, AF_INET,  TCP_TABLE_OWNER_PID_ALL, MibTcpRowOwnerPid,  Protocol::Tcp, "GetExtendedTcpTable");
    scan_table!(port_map, GetExtendedUdpTable, AF_INET,  UDP_TABLE_OWNER_PID,     MibUdpRowOwnerPid,  Protocol::Udp, "GetExtendedUdpTable");
    scan_table!(port_map, GetExtendedTcpTable, AF_INET6, TCP_TABLE_OWNER_PID_ALL, MibTcp6RowOwnerPid, Protocol::Tcp, "GetExtendedTcpTable(AF_INET6)");
    scan_table!(port_map, GetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID,     MibUdp6RowOwnerPid, Protocol::Udp, "GetExtendedUdpTable(AF_INET6)");
}
