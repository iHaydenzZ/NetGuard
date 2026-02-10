mod capture;
mod commands;
mod core;
mod db;

use std::sync::Arc;

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

    let app_state = AppState {
        process_mapper: Arc::clone(&process_mapper),
        traffic_tracker: Arc::clone(&traffic_tracker),
        rate_limiter: Arc::clone(&rate_limiter),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::get_traffic_stats,
            commands::set_bandwidth_limit,
            commands::remove_bandwidth_limit,
            commands::get_bandwidth_limits,
        ])
        .setup(move |app| {
            let app_handle = app.handle().clone();

            // Spawn the process scanner task (500ms refresh).
            process_mapper.start_scanning();

            // Spawn the stats aggregator task (1s tick, emits traffic-stats events).
            traffic_tracker.start_aggregator(Arc::clone(&process_mapper), app_handle);

            // Start packet capture in SNIFF mode (Phase 1 — zero risk).
            match capture::CaptureEngine::start_sniff(
                Arc::clone(&process_mapper),
                Arc::clone(&traffic_tracker),
            ) {
                Ok(engine) => {
                    // Leak to keep alive for the app's lifetime; Drop runs on process exit.
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
