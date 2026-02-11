//! Core logic: traffic accounting, rate limiting, process mapping.
//!
//! - [`TrafficTracker`] — per-process byte counters with speed calculation
//! - [`RateLimiterManager`] / [`BandwidthLimit`] — token bucket rate limiting
//! - [`ProcessMapper`] — PID ↔ port resolution and icon caching
//! - [`icon_extractor`] — Win32 icon extraction and BMP encoding
//! - [`win_net_table`] — iphlpapi FFI for TCP/UDP port tables

pub mod icon_extractor;
pub mod process_mapper;
pub mod rate_limiter;
pub mod traffic;
pub mod win_net_table;

pub use process_mapper::ProcessMapper;
pub use rate_limiter::{BandwidthLimit, RateLimiterManager};
pub use traffic::{ProcessTrafficSnapshot, TrafficTracker};
