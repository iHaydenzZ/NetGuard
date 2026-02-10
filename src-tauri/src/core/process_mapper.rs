//! Maps network connections (ports) to process IDs using the `sysinfo` crate.
//!
//! Refreshes at 500ms intervals via a dedicated tokio task.
//! Results stored in a DashMap<port, PID> for lock-free lookup.
