mod capture;
mod commands;
mod core;
mod db;

use std::sync::Arc;

use tauri::Manager;

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
            traffic_tracker.start_aggregator(Arc::clone(&process_mapper), app_handle);

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

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
