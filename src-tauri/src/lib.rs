mod capture;
mod commands;
mod config;
mod core;
mod db;
mod error;
mod services;

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager,
};

use commands::AppState;
use core::process_mapper::ProcessMapper;
use core::rate_limiter::RateLimiterManager;
use core::traffic::TrafficTracker;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!("PANIC in NetGuard: {info}");
        default_hook(info);
    }));

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "netguard=info".into()),
        )
        .init();

    let process_mapper = Arc::new(ProcessMapper::new());
    let traffic_tracker = Arc::new(TrafficTracker::new());
    let rate_limiter = Arc::new(RateLimiterManager::new());
    let notification_threshold = Arc::new(AtomicU64::new(0));
    let persistent_rules: Arc<Mutex<Vec<db::SavedRule>>> = Arc::new(Mutex::new(Vec::new()));

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::traffic::get_traffic_stats,
            commands::traffic::get_process_icon,
            commands::traffic::get_traffic_history,
            commands::traffic::get_top_consumers,
            commands::rules::set_bandwidth_limit,
            commands::rules::remove_bandwidth_limit,
            commands::rules::get_bandwidth_limits,
            commands::rules::block_process,
            commands::rules::unblock_process,
            commands::rules::get_blocked_pids,
            commands::rules::save_profile,
            commands::rules::apply_profile,
            commands::rules::list_profiles,
            commands::rules::delete_profile,
            commands::rules::get_profile_rules,
            commands::system::set_notification_threshold,
            commands::system::get_notification_threshold,
            commands::system::set_autostart,
            commands::system::get_autostart,
            commands::system::enable_intercept_mode,
            commands::system::disable_intercept_mode,
            commands::system::is_intercept_active,
        ])
        .setup(move |app| {
            let app_handle = app.handle().clone();

            let app_data_dir = app.path().app_data_dir().expect("failed to resolve app data dir");
            std::fs::create_dir_all(&app_data_dir)?;
            let db_path = app_data_dir.join("netguard.db");
            let database = Arc::new(db::Database::open(&db_path).expect("Failed to open SQLite database"));
            tracing::info!("Database opened at {}", db_path.display());

            app.manage(AppState {
                process_mapper: Arc::clone(&process_mapper),
                traffic_tracker: Arc::clone(&traffic_tracker),
                rate_limiter: Arc::clone(&rate_limiter),
                database: Arc::clone(&database),
                notification_threshold_bps: Arc::clone(&notification_threshold),
                persistent_rules: Arc::clone(&persistent_rules),
                sniff_engine: std::sync::Mutex::new(None),
                intercept_engine: std::sync::Mutex::new(None),
            });

            // Start all background services in dependency order.
            services::BackgroundServices::start(
                &process_mapper,
                &traffic_tracker,
                &rate_limiter,
                &database,
                &notification_threshold,
                &persistent_rules,
                app_handle,
            );

            // Start packet capture in SNIFF mode (Phase 1 — zero risk).
            match capture::CaptureEngine::start_sniff(
                Arc::clone(&process_mapper),
                Arc::clone(&traffic_tracker),
            ) {
                Ok(engine) => {
                    let state: tauri::State<AppState> = app.state();
                    *state.sniff_engine.lock().unwrap() = Some(engine);
                    tracing::info!("NetGuard monitoring started (SNIFF mode)");
                }
                Err(e) => {
                    tracing::warn!("Packet capture unavailable: {e:#}. Running in process-scan-only mode.");
                }
            }

            // --- F6: System Tray ---
            let show_item = MenuItem::with_id(app, "show", "Show NetGuard", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_item, &quit_item])?;

            let _tray = TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().cloned().unwrap())
                .tooltip("NetGuard")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
