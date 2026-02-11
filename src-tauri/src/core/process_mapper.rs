//! Maps network connections (ports) to process IDs.
//!
//! Windows: GetExtendedTcpTable/GetExtendedUdpTable from iphlpapi.
//! Refreshes at configurable intervals via a dedicated OS thread.
//! Results stored in DashMap for lock-free lookup.

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

    /// Look up the PID that owns the given (protocol, local_port).
    pub fn lookup_pid(&self, proto: Protocol, local_port: u16) -> Option<u32> {
        self.port_map.get(&(proto, local_port)).map(|r| *r)
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

    /// Spawn a background thread refreshing the maps at the configured interval.
    pub fn start_scanning(self: &Arc<Self>) {
        let mapper = Arc::clone(self);
        std::thread::Builder::new()
            .name("process-scanner".into())
            .spawn(move || {
                let mut sys = System::new();
                loop {
                    win_net_table::refresh_port_map(&mapper.port_map);
                    mapper.refresh_process_info(&mut sys);
                    std::thread::sleep(std::time::Duration::from_millis(
                        config::PROCESS_SCAN_INTERVAL_MS,
                    ));
                }
            })
            .expect("failed to spawn process scanner thread");
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_mapper_empty() {
        let mapper = ProcessMapper::new();
        assert_eq!(mapper.lookup_pid(Protocol::Tcp, 80), None);
        assert_eq!(mapper.lookup_pid(Protocol::Udp, 53), None);
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
}
