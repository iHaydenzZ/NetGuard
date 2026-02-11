//! Tauri IPC command handlers, organized by functional domain.
//!
//! - `traffic`: F1 monitoring, F4 history, AC-1.6 icons
//! - `rules`: F2 bandwidth limiting, F3 blocking, F5 profiles
//! - `system`: F6 notifications, F7 auto-start, intercept mode
//! - `logic`: Pure business logic functions (unit-testable)
//! - `state`: Shared `AppState` definition

mod logic;
pub(crate) mod rules;
mod state;
pub(crate) mod system;
pub(crate) mod traffic;

pub use state::AppState;
