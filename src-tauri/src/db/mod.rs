//! SQLite persistence layer for traffic history and bandwidth rules.
//!
//! Uses `rusqlite` with bundled SQLite. Handles:
//! - Per-process traffic history (5-second granularity)
//! - Bandwidth rule profiles
//! - Auto-pruning of data older than 90 days
