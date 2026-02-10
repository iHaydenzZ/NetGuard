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
#[allow(dead_code)] // Variants used by Windows backend; tested on all platforms.
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
    #[allow(dead_code)] // Used by Windows backend.
    pub fn lookup_pid(&self, proto: Protocol, local_port: u16) -> Option<u32> {
        self.port_map.get(&(proto, local_port)).map(|r| *r)
    }

    /// Get process info for a PID.
    pub fn get_process_info(&self, pid: u32) -> Option<ProcessInfo> {
        self.process_info.get(&pid).map(|r| r.clone())
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

    /// Spawn a background thread refreshing the maps every 500ms.
    /// Uses a plain OS thread instead of tokio::spawn to avoid requiring
    /// a Tokio runtime context at call site (Tauri setup runs before runtime is ready).
    pub fn start_scanning(self: &Arc<Self>) {
        let mapper = Arc::clone(self);
        std::thread::Builder::new()
            .name("process-scanner".into())
            .spawn(move || {
                let mut sys = System::new();
                loop {
                    mapper.refresh_port_map();
                    mapper.refresh_process_info(&mut sys);
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            })
            .expect("failed to spawn process scanner thread");
    }

    /// Return a cached base64 data-URI icon for the given exe path (AC-1.6).
    /// Extracts the icon on first call and caches for subsequent lookups.
    pub fn get_icon_base64(&self, exe_path: &str) -> Option<String> {
        if exe_path.is_empty() {
            return None;
        }
        if let Some(cached) = self.icon_cache.get(exe_path) {
            return cached.value().clone();
        }
        let icon = Self::extract_icon(exe_path);
        self.icon_cache.insert(exe_path.to_string(), icon.clone());
        icon
    }

    /// Platform-specific icon extraction. Windows uses Shell32 + GDI;
    /// macOS returns None (stub for Phase 3).
    #[cfg(target_os = "windows")]
    fn extract_icon(exe_path: &str) -> Option<String> {
        use self::win_icon_api::*;
        use base64::Engine as _;

        // Convert exe path to null-terminated wide string.
        let wide: Vec<u16> = exe_path.encode_utf16().chain(std::iter::once(0)).collect();

        let mut h_small: usize = 0;
        let count =
            unsafe { ExtractIconExW(wide.as_ptr(), 0, std::ptr::null_mut(), &mut h_small, 1) };
        if count == 0 || h_small == 0 {
            tracing::trace!("No icon found for {exe_path}");
            return None;
        }

        // Ensure cleanup on all exit paths.
        let result = (|| -> Option<String> {
            // Get icon bitmap handles.
            let mut icon_info: ICONINFO = unsafe { std::mem::zeroed() };
            if unsafe { GetIconInfo(h_small, &mut icon_info) } == 0 {
                return None;
            }

            // Get bitmap dimensions from the color bitmap.
            let mut bm: BITMAP = unsafe { std::mem::zeroed() };
            let obj_ret = unsafe {
                GetObjectW(
                    icon_info.hbmColor,
                    std::mem::size_of::<BITMAP>() as i32,
                    &mut bm as *mut BITMAP as *mut u8,
                )
            };
            if obj_ret == 0 {
                unsafe {
                    DeleteObject(icon_info.hbmMask);
                    DeleteObject(icon_info.hbmColor);
                }
                return None;
            }

            let width = bm.bmWidth;
            let height = bm.bmHeight;
            if width <= 0 || height <= 0 || width > 256 || height > 256 {
                unsafe {
                    DeleteObject(icon_info.hbmMask);
                    DeleteObject(icon_info.hbmColor);
                }
                return None;
            }

            // Create a compatible DC.
            let hdc = unsafe { CreateCompatibleDC(0) };
            if hdc == 0 {
                unsafe {
                    DeleteObject(icon_info.hbmMask);
                    DeleteObject(icon_info.hbmColor);
                }
                return None;
            }

            // Set up BITMAPINFO for 32-bit top-down DIB.
            let mut bmi: BITMAPINFO = unsafe { std::mem::zeroed() };
            bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
            bmi.bmiHeader.biWidth = width;
            bmi.bmiHeader.biHeight = -height; // negative = top-down
            bmi.bmiHeader.biPlanes = 1;
            bmi.bmiHeader.biBitCount = 32;
            bmi.bmiHeader.biCompression = 0; // BI_RGB

            let pixel_count = (width * height) as usize;
            let mut pixels = vec![0u8; pixel_count * 4]; // BGRA

            let scan_ret = unsafe {
                GetDIBits(
                    hdc,
                    icon_info.hbmColor,
                    0,
                    height as u32,
                    pixels.as_mut_ptr(),
                    &mut bmi,
                    0, // DIB_RGB_COLORS
                )
            };

            // Clean up GDI resources.
            unsafe {
                DeleteDC(hdc);
                DeleteObject(icon_info.hbmMask);
                DeleteObject(icon_info.hbmColor);
            }

            if scan_ret == 0 {
                return None;
            }

            // Build a BMP file in memory.
            // BMP file header (14 bytes) + DIB header (40 bytes) + pixel data.
            let row_bytes = (width as usize) * 4;
            // BMP rows must be aligned to 4 bytes; at 32bpp this is always satisfied.
            let pixel_data_size = row_bytes * (height as usize);
            let file_size = 14 + 40 + pixel_data_size;
            let mut bmp = Vec::with_capacity(file_size);

            // -- BMP File Header (14 bytes) --
            bmp.extend_from_slice(b"BM"); // signature
            bmp.extend_from_slice(&(file_size as u32).to_le_bytes()); // file size
            bmp.extend_from_slice(&0u16.to_le_bytes()); // reserved1
            bmp.extend_from_slice(&0u16.to_le_bytes()); // reserved2
            bmp.extend_from_slice(&54u32.to_le_bytes()); // pixel data offset

            // -- DIB Header (BITMAPINFOHEADER, 40 bytes) --
            bmp.extend_from_slice(&40u32.to_le_bytes()); // header size
            bmp.extend_from_slice(&(width).to_le_bytes()); // width
                                                           // BMP stores bottom-up by default; use positive height and flip rows.
            bmp.extend_from_slice(&(height).to_le_bytes()); // height (positive = bottom-up)
            bmp.extend_from_slice(&1u16.to_le_bytes()); // planes
            bmp.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
            bmp.extend_from_slice(&0u32.to_le_bytes()); // compression (BI_RGB)
            bmp.extend_from_slice(&(pixel_data_size as u32).to_le_bytes()); // image size
            bmp.extend_from_slice(&0i32.to_le_bytes()); // x pixels per meter
            bmp.extend_from_slice(&0i32.to_le_bytes()); // y pixels per meter
            bmp.extend_from_slice(&0u32.to_le_bytes()); // colors used
            bmp.extend_from_slice(&0u32.to_le_bytes()); // important colors

            // -- Pixel data (bottom-up row order for BMP) --
            // Our pixel buffer is top-down (row 0 = top), BMP expects bottom-up.
            for y in (0..height as usize).rev() {
                let row_start = y * row_bytes;
                bmp.extend_from_slice(&pixels[row_start..row_start + row_bytes]);
            }

            let encoded = base64::engine::general_purpose::STANDARD.encode(&bmp);
            Some(format!("data:image/bmp;base64,{encoded}"))
        })();

        // Always destroy the icon handle.
        unsafe {
            DestroyIcon(h_small);
        }

        result
    }

    /// macOS stub — icon extraction not yet implemented.
    #[cfg(target_os = "macos")]
    fn extract_icon(_exe_path: &str) -> Option<String> {
        None
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
        // IPv4
        self.scan_tcp_table();
        self.scan_udp_table();
        // IPv6
        self.scan_tcp6_table();
        self.scan_udp6_table();
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

    #[cfg(target_os = "windows")]
    fn scan_tcp6_table(&self) {
        use self::win_port_api::*;

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
                self.port_map.insert((Protocol::Tcp, port), row.owning_pid);
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn scan_udp6_table(&self) {
        use self::win_port_api::*;

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
}

// ---------------------------------------------------------------------------
// Windows FFI for Shell32/GDI icon extraction (AC-1.6)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[allow(non_snake_case)]
mod win_icon_api {
    #[link(name = "shell32")]
    extern "system" {
        pub fn ExtractIconExW(
            lpszFile: *const u16,
            nIconIndex: i32,
            phiconLarge: *mut usize, // HICON
            phiconSmall: *mut usize, // HICON
            nIcons: u32,
        ) -> u32;
    }

    #[link(name = "user32")]
    extern "system" {
        pub fn DestroyIcon(hIcon: usize) -> i32;
        pub fn GetIconInfo(hIcon: usize, piconinfo: *mut ICONINFO) -> i32;
    }

    #[link(name = "gdi32")]
    extern "system" {
        pub fn GetDIBits(
            hdc: usize,
            hbm: usize,
            start: u32,
            cLines: u32,
            lpvBits: *mut u8,
            lpbmi: *mut BITMAPINFO,
            usage: u32,
        ) -> i32;
        pub fn CreateCompatibleDC(hdc: usize) -> usize;
        pub fn DeleteDC(hdc: usize) -> i32;
        pub fn DeleteObject(ho: usize) -> i32;
        pub fn GetObjectW(h: usize, c: i32, pv: *mut u8) -> i32;
    }

    #[repr(C)]
    #[allow(clippy::upper_case_acronyms)]
    pub struct ICONINFO {
        pub fIcon: i32,
        pub xHotspot: u32,
        pub yHotspot: u32,
        pub hbmMask: usize,
        pub hbmColor: usize,
    }

    #[repr(C)]
    #[allow(clippy::upper_case_acronyms)]
    pub struct BITMAPINFOHEADER {
        pub biSize: u32,
        pub biWidth: i32,
        pub biHeight: i32,
        pub biPlanes: u16,
        pub biBitCount: u16,
        pub biCompression: u32,
        pub biSizeImage: u32,
        pub biXPelsPerMeter: i32,
        pub biYPelsPerMeter: i32,
        pub biClrUsed: u32,
        pub biClrImportant: u32,
    }

    #[repr(C)]
    #[allow(clippy::upper_case_acronyms)]
    pub struct BITMAPINFO {
        pub bmiHeader: BITMAPINFOHEADER,
        pub bmiColors: [u32; 1],
    }

    #[repr(C)]
    #[allow(clippy::upper_case_acronyms)]
    pub struct BITMAP {
        pub bmType: i32,
        pub bmWidth: i32,
        pub bmHeight: i32,
        pub bmWidthBytes: i32,
        pub bmPlanes: u16,
        pub bmBitsPixel: u16,
        pub bmBits: *mut u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_mapper_empty() {
        let mapper = ProcessMapper::new();
        // Lookup on an empty mapper should return None for any protocol/port.
        assert_eq!(
            mapper.lookup_pid(Protocol::Tcp, 80),
            None,
            "empty mapper should return None for TCP port 80"
        );
        assert_eq!(
            mapper.lookup_pid(Protocol::Udp, 53),
            None,
            "empty mapper should return None for UDP port 53"
        );
    }

    #[test]
    fn test_get_process_info_unknown_pid() {
        let mapper = ProcessMapper::new();
        assert!(
            mapper.get_process_info(12345).is_none(),
            "unknown PID should return None"
        );
        assert!(
            mapper.get_process_info(0).is_none(),
            "PID 0 should return None on empty mapper"
        );
    }

    #[test]
    fn test_connection_counts_empty() {
        let mapper = ProcessMapper::new();
        let counts = mapper.connection_counts();
        assert!(
            counts.is_empty(),
            "empty mapper should have no connection counts"
        );
    }
}
