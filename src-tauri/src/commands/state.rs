//! Shared application state managed by Tauri.

use std::sync::Arc;

use crate::capture::CaptureEngine;
use crate::core::process_mapper::ProcessMapper;
use crate::core::rate_limiter::RateLimiterManager;
use crate::core::traffic::TrafficTracker;
use crate::db::{self, Database};

/// Shared application state managed by Tauri.
pub struct AppState {
    pub process_mapper: Arc<ProcessMapper>,
    pub traffic_tracker: Arc<TrafficTracker>,
    pub rate_limiter: Arc<RateLimiterManager>,
    pub database: Arc<Database>,
    /// Bandwidth threshold for notifications (bytes/sec, 0 = disabled). (AC-6.4)
    pub notification_threshold_bps: Arc<std::sync::atomic::AtomicU64>,
    /// Persistent rules from the active profile, auto-applied to new processes. (F7)
    pub persistent_rules: Arc<std::sync::Mutex<Vec<db::SavedRule>>>,
    /// Active SNIFF engine (stopped when intercept is active to avoid double-counting).
    pub sniff_engine: std::sync::Mutex<Option<CaptureEngine>>,
    /// Active intercept engine (None when in SNIFF-only mode). (Phase 2)
    pub intercept_engine: std::sync::Mutex<Option<CaptureEngine>>,
}
