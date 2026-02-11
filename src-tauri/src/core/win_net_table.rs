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

/// Scan all TCP and UDP tables (IPv4 + IPv6) and populate the port map.
pub fn refresh_port_map(port_map: &DashMap<(Protocol, u16), u32>) {
    port_map.clear();
    scan_tcp_table(port_map);
    scan_udp_table(port_map);
    scan_tcp6_table(port_map);
    scan_udp6_table(port_map);
}

fn scan_tcp_table(port_map: &DashMap<(Protocol, u16), u32>) {
    let mut size: u32 = 0;
    let ret = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if ret != ERROR_INSUFFICIENT_BUFFER {
        return;
    }

    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedTcpTable(
            buf.as_mut_ptr(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if ret != NO_ERROR {
        tracing::warn!("GetExtendedTcpTable failed with code {ret}");
        return;
    }

    if buf.len() < 4 {
        return;
    }
    let num_entries = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
    let row_size = std::mem::size_of::<MibTcpRowOwnerPid>();

    for i in 0..num_entries {
        let offset = 4 + i * row_size;
        if offset + row_size > buf.len() {
            break;
        }
        let row = unsafe { &*(buf.as_ptr().add(offset) as *const MibTcpRowOwnerPid) };
        let port = u16::from_be(row.local_port as u16);
        if port > 0 && row.owning_pid > 0 {
            port_map.insert((Protocol::Tcp, port), row.owning_pid);
        }
    }
}

fn scan_udp_table(port_map: &DashMap<(Protocol, u16), u32>) {
    let mut size: u32 = 0;
    let ret = unsafe {
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if ret != ERROR_INSUFFICIENT_BUFFER {
        return;
    }

    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedUdpTable(
            buf.as_mut_ptr(),
            &mut size,
            0,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if ret != NO_ERROR {
        tracing::warn!("GetExtendedUdpTable failed with code {ret}");
        return;
    }

    if buf.len() < 4 {
        return;
    }
    let num_entries = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
    let row_size = std::mem::size_of::<MibUdpRowOwnerPid>();

    for i in 0..num_entries {
        let offset = 4 + i * row_size;
        if offset + row_size > buf.len() {
            break;
        }
        let row = unsafe { &*(buf.as_ptr().add(offset) as *const MibUdpRowOwnerPid) };
        let port = u16::from_be(row.local_port as u16);
        if port > 0 && row.owning_pid > 0 {
            port_map.insert((Protocol::Udp, port), row.owning_pid);
        }
    }
}

fn scan_tcp6_table(port_map: &DashMap<(Protocol, u16), u32>) {
    let mut size: u32 = 0;
    let ret = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if ret != ERROR_INSUFFICIENT_BUFFER {
        return;
    }

    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedTcpTable(
            buf.as_mut_ptr(),
            &mut size,
            0,
            AF_INET6,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if ret != NO_ERROR {
        tracing::warn!("GetExtendedTcpTable(AF_INET6) failed with code {ret}");
        return;
    }

    if buf.len() < 4 {
        return;
    }
    let num_entries = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
    let row_size = std::mem::size_of::<MibTcp6RowOwnerPid>();

    for i in 0..num_entries {
        let offset = 4 + i * row_size;
        if offset + row_size > buf.len() {
            break;
        }
        let row = unsafe { &*(buf.as_ptr().add(offset) as *const MibTcp6RowOwnerPid) };
        let port = u16::from_be(row.local_port as u16);
        if port > 0 && row.owning_pid > 0 {
            port_map.insert((Protocol::Tcp, port), row.owning_pid);
        }
    }
}

fn scan_udp6_table(port_map: &DashMap<(Protocol, u16), u32>) {
    let mut size: u32 = 0;
    let ret = unsafe {
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if ret != ERROR_INSUFFICIENT_BUFFER {
        return;
    }

    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedUdpTable(
            buf.as_mut_ptr(),
            &mut size,
            0,
            AF_INET6,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if ret != NO_ERROR {
        tracing::warn!("GetExtendedUdpTable(AF_INET6) failed with code {ret}");
        return;
    }

    if buf.len() < 4 {
        return;
    }
    let num_entries = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
    let row_size = std::mem::size_of::<MibUdp6RowOwnerPid>();

    for i in 0..num_entries {
        let offset = 4 + i * row_size;
        if offset + row_size > buf.len() {
            break;
        }
        let row = unsafe { &*(buf.as_ptr().add(offset) as *const MibUdp6RowOwnerPid) };
        let port = u16::from_be(row.local_port as u16);
        if port > 0 && row.owning_pid > 0 {
            port_map.insert((Protocol::Udp, port), row.owning_pid);
        }
    }
}
