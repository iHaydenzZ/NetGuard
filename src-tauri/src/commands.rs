/// Tauri IPC command handlers.
/// All #[tauri::command] functions go here and are registered in lib.rs.

#[tauri::command]
pub fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}
