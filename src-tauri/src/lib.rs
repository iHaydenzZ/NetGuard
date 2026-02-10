mod capture;
mod commands;
mod core;
mod db;

use std::sync::Arc;

use tauri::{
    Manager,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

use commands::AppState;
use core::process_mapper::ProcessMapper;
use core::rate_limiter::RateLimiterManager;
use core::traffic::TrafficTracker;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Custom panic hook for safety logging (PRD S4).
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

    // Build shared state.
    let process_mapper = Arc::new(ProcessMapper::new());
    let traffic_tracker = Arc::new(TrafficTracker::new());
    let rate_limiter = Arc::new(RateLimiterManager::new());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::get_traffic_stats,
            commands::set_bandwidth_limit,
            commands::remove_bandwidth_limit,
            commands::get_bandwidth_limits,
            commands::block_process,
            commands::unblock_process,
            commands::get_blocked_pids,
            commands::get_traffic_history,
            commands::get_top_consumers,
            commands::save_profile,
            commands::apply_profile,
            commands::list_profiles,
            commands::delete_profile,
            commands::get_profile_rules,
        ])
        .setup(move |app| {
            let app_handle = app.handle().clone();

            // Open the SQLite database in the app's data directory.
            let app_data_dir = app
                .path()
                .app_data_dir()
                .expect("failed to resolve app data dir");
            std::fs::create_dir_all(&app_data_dir)?;
            let db_path = app_data_dir.join("netguard.db");
            let database = Arc::new(
                db::Database::open(&db_path)
                    .expect("Failed to open SQLite database"),
            );
            tracing::info!("Database opened at {}", db_path.display());

            // Register AppState with the database included.
            app.manage(AppState {
                process_mapper: Arc::clone(&process_mapper),
                traffic_tracker: Arc::clone(&traffic_tracker),
                rate_limiter: Arc::clone(&rate_limiter),
                database: Arc::clone(&database),
            });

            // Spawn the process scanner task (500ms refresh).
            process_mapper.start_scanning();

            // Spawn the stats aggregator task (1s tick, emits traffic-stats events).
            traffic_tracker.start_aggregator(Arc::clone(&process_mapper), app_handle.clone());

            // Spawn the history recording task (5s interval) and daily pruning.
            {
                let tracker = Arc::clone(&traffic_tracker);
                let mapper = Arc::clone(&process_mapper);
                let db = Arc::clone(&database);
                tokio::spawn(async move {
                    let mut ticker =
                        tokio::time::interval(std::time::Duration::from_secs(5));
                    let mut prune_counter = 0u64;
                    loop {
                        ticker.tick().await;
                        let snapshot = tracker.snapshot(&mapper);
                        let now = db::chrono_timestamp();
                        let records: Vec<db::TrafficRecord> = snapshot
                            .iter()
                            .filter(|s| s.upload_speed > 0.0 || s.download_speed > 0.0)
                            .map(|s| db::TrafficRecord {
                                timestamp: now,
                                pid: s.pid,
                                process_name: s.name.clone(),
                                exe_path: s.exe_path.clone(),
                                bytes_sent: s.bytes_sent,
                                bytes_recv: s.bytes_recv,
                                upload_speed: s.upload_speed,
                                download_speed: s.download_speed,
                            })
                            .collect();
                        if !records.is_empty() {
                            if let Err(e) = db.insert_traffic_batch(&records) {
                                tracing::warn!("Failed to record traffic history: {e}");
                            }
                        }

                        // Prune old records roughly once per day (every ~17280 ticks at 5s).
                        prune_counter += 1;
                        if prune_counter % 17280 == 0 {
                            if let Err(e) = db.prune_old_records(90) {
                                tracing::warn!("Failed to prune old records: {e}");
                            }
                        }
                    }
                });
            }

            // Start packet capture in SNIFF mode (Phase 1 — zero risk).
            match capture::CaptureEngine::start_sniff(
                Arc::clone(&process_mapper),
                Arc::clone(&traffic_tracker),
            ) {
                Ok(engine) => {
                    Box::leak(Box::new(engine));
                    tracing::info!("NetGuard monitoring started (SNIFF mode)");
                }
                Err(e) => {
                    tracing::warn!(
                        "Packet capture unavailable: {e:#}. Running in process-scan-only mode."
                    );
                }
            }

            // --- F6: System Tray (AC-6.1, AC-6.2, AC-6.3) ---
            let show_item =
                MenuItem::with_id(app, "show", "Show NetGuard", true, None::<&str>)?;
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
                    "quit" => {
                        app.exit(0);
                    }
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

            // Spawn tray tooltip + menu updater (2s interval, AC-6.2 + AC-6.3).
            {
                let tracker = Arc::clone(&traffic_tracker);
                let mapper = Arc::clone(&process_mapper);
                let handle = app_handle.clone();
                tokio::spawn(async move {
                    let mut ticker =
                        tokio::time::interval(std::time::Duration::from_secs(2));
                    loop {
                        ticker.tick().await;
                        update_tray(&handle, &tracker, &mapper);
                    }
                });
            }

            Ok(())
        })
        // AC-6.1: Close window minimizes to tray instead of quitting.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Update the system tray tooltip and right-click menu with current traffic data.
fn update_tray(app: &tauri::AppHandle, tracker: &TrafficTracker, mapper: &ProcessMapper) {
    let snapshot = tracker.snapshot(mapper);
    let total_down: f64 = snapshot.iter().map(|s| s.download_speed).sum();
    let total_up: f64 = snapshot.iter().map(|s| s.upload_speed).sum();

    let tooltip = format!(
        "NetGuard\n\u{2193} {} \u{2191} {}",
        format_speed_compact(total_down),
        format_speed_compact(total_up)
    );

    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(&tooltip));

        // Top 5 active consumers by total speed (AC-6.3).
        let mut active: Vec<_> = snapshot
            .into_iter()
            .filter(|s| s.download_speed > 0.0 || s.upload_speed > 0.0)
            .collect();
        active.sort_by(|a, b| {
            (b.download_speed + b.upload_speed)
                .partial_cmp(&(a.download_speed + a.upload_speed))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        active.truncate(5);

        if let Ok(menu) = build_tray_menu(app, &active) {
            let _ = tray.set_menu(Some(menu));
        }
    }
}

/// Build a tray right-click menu with top consumers and action items.
fn build_tray_menu(
    app: &tauri::AppHandle,
    top_consumers: &[core::traffic::ProcessTrafficSnapshot],
) -> anyhow::Result<tauri::menu::Menu<tauri::Wry>> {
    let menu = Menu::new(app)?;

    for (i, proc) in top_consumers.iter().enumerate() {
        let label = format!(
            "{}: \u{2193}{} \u{2191}{}",
            proc.name,
            format_speed_compact(proc.download_speed),
            format_speed_compact(proc.upload_speed)
        );
        let item =
            MenuItem::with_id(app, format!("consumer_{i}"), &label, false, None::<&str>)?;
        menu.append(&item)?;
    }

    if !top_consumers.is_empty() {
        menu.append(&PredefinedMenuItem::separator(app)?)?;
    }

    menu.append(&MenuItem::with_id(
        app, "show", "Show NetGuard", true, None::<&str>,
    )?)?;
    menu.append(&MenuItem::with_id(
        app, "quit", "Quit", true, None::<&str>,
    )?)?;

    Ok(menu)
}

fn format_speed_compact(bps: f64) -> String {
    if bps < 1024.0 {
        format!("{:.0} B/s", bps)
    } else if bps < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", bps / 1024.0)
    } else {
        format!("{:.2} MB/s", bps / (1024.0 * 1024.0))
    }
}
