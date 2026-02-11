mod capture;
mod commands;
mod config;
mod core;
mod db;
mod error;

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager,
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
    let notification_threshold = Arc::new(AtomicU64::new(0));
    let persistent_rules: Arc<Mutex<Vec<db::SavedRule>>> = Arc::new(Mutex::new(Vec::new()));

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::get_traffic_stats,
            commands::get_process_icon,
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
            commands::set_notification_threshold,
            commands::get_notification_threshold,
            commands::set_autostart,
            commands::get_autostart,
            commands::enable_intercept_mode,
            commands::disable_intercept_mode,
            commands::is_intercept_active,
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
            let database =
                Arc::new(db::Database::open(&db_path).expect("Failed to open SQLite database"));
            tracing::info!("Database opened at {}", db_path.display());

            // Register AppState with the database included.
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

            // Spawn the process scanner task (500ms refresh).
            process_mapper.start_scanning();

            // Spawn the stats aggregator task (1s tick, emits traffic-stats events).
            traffic_tracker.start_aggregator(Arc::clone(&process_mapper), app_handle.clone());

            // Spawn the history recording thread (5s interval) and daily pruning.
            // Uses a plain OS thread to avoid requiring a Tokio runtime context.
            {
                let tracker = Arc::clone(&traffic_tracker);
                let mapper = Arc::clone(&process_mapper);
                let db = Arc::clone(&database);
                std::thread::Builder::new()
                    .name("history-recorder".into())
                    .spawn(move || {
                        let mut prune_counter = 0u64;
                        loop {
                            std::thread::sleep(std::time::Duration::from_secs(config::HISTORY_RECORD_INTERVAL_SECS));
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
                            if prune_counter % config::PRUNE_CHECK_INTERVAL_TICKS == 0 {
                                if let Err(e) = db.prune_old_records(config::PRUNE_MAX_AGE_DAYS) {
                                    tracing::warn!("Failed to prune old records: {e}");
                                }
                            }
                        }
                    })
                    .expect("failed to spawn history recorder thread");
            }

            // Start packet capture in SNIFF mode (Phase 1 — zero risk).
            // Stored in AppState so it can be stopped when switching to intercept mode
            // (prevents double-counting: both SNIFF and INTERCEPT loops call record_bytes).
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
                    tracing::warn!(
                        "Packet capture unavailable: {e:#}. Running in process-scan-only mode."
                    );
                }
            }

            // --- F6: System Tray (AC-6.1, AC-6.2, AC-6.3) ---
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

            // Spawn tray tooltip + menu updater + threshold checker (2s interval).
            // Uses a plain OS thread to avoid requiring a Tokio runtime context.
            {
                let tracker = Arc::clone(&traffic_tracker);
                let mapper = Arc::clone(&process_mapper);
                let handle = app_handle.clone();
                let threshold = Arc::clone(&notification_threshold);
                std::thread::Builder::new()
                    .name("tray-updater".into())
                    .spawn(move || {
                        let mut notified_pids: HashSet<u32> = HashSet::new();
                        loop {
                            std::thread::sleep(std::time::Duration::from_secs(config::TRAY_UPDATE_INTERVAL_SECS));
                            update_tray_and_notify(
                                &handle,
                                &tracker,
                                &mapper,
                                &threshold,
                                &mut notified_pids,
                            );
                        }
                    })
                    .expect("failed to spawn tray updater thread");
            }

            // F7 (AC-7.2, AC-7.3): Auto-apply persistent rules to newly launched processes.
            // Uses a plain OS thread to avoid requiring a Tokio runtime context.
            {
                let tracker = Arc::clone(&traffic_tracker);
                let mapper = Arc::clone(&process_mapper);
                let limiter = Arc::clone(&rate_limiter);
                let rules = Arc::clone(&persistent_rules);
                std::thread::Builder::new()
                    .name("persistent-rules".into())
                    .spawn(move || loop {
                        std::thread::sleep(std::time::Duration::from_secs(config::PERSISTENT_RULES_INTERVAL_SECS));
                        apply_persistent_rules(&tracker, &mapper, &limiter, &rules);
                    })
                    .expect("failed to spawn persistent rules thread");
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

/// Update tray tooltip/menu and check bandwidth threshold notifications.
fn update_tray_and_notify(
    app: &tauri::AppHandle,
    tracker: &TrafficTracker,
    mapper: &ProcessMapper,
    threshold: &AtomicU64,
    notified_pids: &mut HashSet<u32>,
) {
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
            .iter()
            .filter(|s| s.download_speed > 0.0 || s.upload_speed > 0.0)
            .cloned()
            .collect::<Vec<_>>();
        active.sort_by(|a, b| {
            (b.download_speed + b.upload_speed)
                .partial_cmp(&(a.download_speed + a.upload_speed))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        active.truncate(config::TRAY_TOP_CONSUMERS_COUNT);

        if let Ok(menu) = build_tray_menu(app, &active) {
            let _ = tray.set_menu(Some(menu));
        }
    }

    // AC-6.4: Bandwidth threshold notifications.
    let threshold_bps = threshold.load(Ordering::Relaxed);
    if threshold_bps > 0 {
        for proc in &snapshot {
            let total_speed = proc.download_speed + proc.upload_speed;
            if total_speed as u64 > threshold_bps {
                if notified_pids.insert(proc.pid) {
                    // First time exceeding — emit notification event.
                    let _ = app.emit(
                        "threshold-exceeded",
                        serde_json::json!({
                            "pid": proc.pid,
                            "name": proc.name,
                            "speed": total_speed,
                            "threshold": threshold_bps,
                        }),
                    );
                    tracing::info!(
                        "Threshold exceeded: {} (PID {}) at {}",
                        proc.name,
                        proc.pid,
                        format_speed_compact(total_speed)
                    );
                }
            } else {
                // Dropped below threshold — allow re-notification.
                notified_pids.remove(&proc.pid);
            }
        }
    }
}

/// F7 (AC-7.2, AC-7.3): Apply persistent rules to running processes.
fn apply_persistent_rules(
    tracker: &TrafficTracker,
    mapper: &ProcessMapper,
    limiter: &RateLimiterManager,
    rules: &Mutex<Vec<db::SavedRule>>,
) {
    let rules_guard = rules.lock().unwrap();
    if rules_guard.is_empty() {
        return;
    }

    let snapshot = tracker.snapshot(mapper);
    for proc in &snapshot {
        for rule in rules_guard.iter() {
            if proc.exe_path == rule.exe_path {
                // Only apply if not already managed.
                if rule.blocked && !limiter.is_blocked(proc.pid) {
                    limiter.block_process(proc.pid);
                    tracing::debug!("Auto-applied block to {} (PID {})", proc.name, proc.pid);
                } else if (rule.download_bps > 0 || rule.upload_bps > 0)
                    && !limiter.is_limited(proc.pid)
                {
                    limiter.set_limit(
                        proc.pid,
                        core::rate_limiter::BandwidthLimit {
                            download_bps: rule.download_bps,
                            upload_bps: rule.upload_bps,
                        },
                    );
                    tracing::debug!(
                        "Auto-applied limit to {} (PID {}): DL={} UL={}",
                        proc.name,
                        proc.pid,
                        rule.download_bps,
                        rule.upload_bps
                    );
                }
            }
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
        let item = MenuItem::with_id(app, format!("consumer_{i}"), &label, false, None::<&str>)?;
        menu.append(&item)?;
    }

    if !top_consumers.is_empty() {
        menu.append(&PredefinedMenuItem::separator(app)?)?;
    }

    menu.append(&MenuItem::with_id(
        app,
        "show",
        "Show NetGuard",
        true,
        None::<&str>,
    )?)?;
    menu.append(&MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?)?;

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
