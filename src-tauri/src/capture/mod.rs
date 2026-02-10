//! Platform-specific packet capture backends.
//!
//! Each platform implements the `PacketBackend` trait:
//! - Windows: WinDivert 2.x (`windivert_backend`)
//! - macOS: pf + dnctl (`pf_backend`)

#[cfg(target_os = "windows")]
pub mod windivert_backend;

#[cfg(target_os = "macos")]
pub mod pf_backend;
