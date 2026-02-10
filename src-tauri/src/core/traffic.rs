//! Per-process traffic accounting using DashMap for lock-free concurrent access.
//!
//! Tracks bytes sent/received per PID, computes 1-second speed snapshots,
//! and emits stats to the frontend via Tauri events.
