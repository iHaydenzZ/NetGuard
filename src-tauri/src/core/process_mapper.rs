//! Maps network connections (ports) to process IDs.
//!
//! Windows: GetExtendedTcpTable/GetExtendedUdpTable from iphlpapi.
//! Refreshes at 500ms intervals via a dedicated tokio task.
//! Results stored in DashMap for lock-free lookup.

use std::sync::Arc;

use dashmap::DashMap;
use serde::Serialize;
use sysinfo::System;

/// Network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Lightweight process metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub name: String,
    pub exe_path: String,
}

/// Thread-safe mapper from (protocol, local_port) to PID and PID to ProcessInfo.
pub struct ProcessMapper {
    /// (Protocol, local_port) -> owning PID.
    port_map: DashMap<(Protocol, u16), u32>,
    /// PID -> process metadata.
    process_info: DashMap<u32, ProcessInfo>,
}

impl ProcessMapper {
    pub fn new() -> Self {
        Self {
            port_map: DashMap::new(),
            process_info: DashMap::new(),
        }
    }

    /// Look up the PID that owns the given (protocol, local_port).
    pub fn lookup_pid(&self, proto: Protocol, local_port: u16) -> Option<u32> {
        self.port_map.get(&(proto, local_port)).map(|r| *r)
    }

    /// Get process info for a PID.
    pub fn get_process_info(&self, pid: u32) -> Option<ProcessInfo> {
        self.process_info.get(&pid).map(|r| r.clone())
    }

    /// Get all PIDs that currently have at least one open port.
    pub fn active_pids(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = self.port_map.iter().map(|r| *r.value()).collect();
        pids.sort_unstable();
        pids.dedup();
        pids
    }

    /// Count active connections per PID. Returns a map of PID -> connection count.
    pub fn connection_counts(&self) -> DashMap<u32, u32> {
        let counts = DashMap::new();
        for entry in self.port_map.iter() {
            let pid = *entry.value();
            counts.entry(pid).and_modify(|c| *c += 1).or_insert(1);
        }
        counts
    }

    /// Spawn a background task refreshing the maps every 500ms.
    pub fn start_scanning(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let mapper = Arc::clone(self);
        tokio::spawn(async move {
            let mut sys = System::new();
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(500));
            loop {
                ticker.tick().await;
                mapper.refresh_port_map();
                mapper.refresh_process_info(&mut sys);
            }
        })
    }

    fn refresh_process_info(&self, sys: &mut System) {
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            self.process_info
                .entry(pid_u32)
                .and_modify(|info| {
                    let name = process.name().to_string_lossy().to_string();
                    if info.name != name {
                        info.name = name;
                    }
                })
                .or_insert_with(|| ProcessInfo {
                    name: process.name().to_string_lossy().to_string(),
                    exe_path: process
                        .exe()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default(),
                });
        }
    }

    #[cfg(target_os = "windows")]
    fn refresh_port_map(&self) {
        self.port_map.clear();
        self.scan_tcp_table();
        self.scan_udp_table();
    }

    #[cfg(target_os = "windows")]
    fn scan_tcp_table(&self) {
        use self::win_port_api::*;

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
                self.port_map.insert((Protocol::Tcp, port), row.owning_pid);
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn scan_udp_table(&self) {
        use self::win_port_api::*;

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
                self.port_map.insert((Protocol::Udp, port), row.owning_pid);
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn refresh_port_map(&self) {
        // Phase 3: macOS implementation using lsof/libproc.
        self.port_map.clear();
    }
}

// ---------------------------------------------------------------------------
// Windows FFI for IP Helper port-to-PID tables
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod win_port_api {
    pub const AF_INET: u32 = 2;
    pub const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    pub const UDP_TABLE_OWNER_PID: u32 = 1;
    pub const NO_ERROR: u32 = 0;
    pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

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
}
