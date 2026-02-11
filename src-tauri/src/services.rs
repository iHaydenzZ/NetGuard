//! Background service lifecycle management.
//!
//! `BackgroundServices` owns all background threads spawned during app setup,
//! starting them in the correct dependency order and providing clean shutdown.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    Emitter,
};

use crate::config;
use crate::core::process_mapper::ProcessMapper;
use crate::core::rate_limiter::{BandwidthLimit, RateLimiterManager};
use crate::core::traffic::{ProcessTrafficSnapshot, TrafficTracker};
use crate::db;

/// Manages all background threads spawned during application setup.
///
/// Threads are started in dependency order:
/// 1. Process scanner (PID ↔ port mapping)
/// 2. Stats aggregator (1s speed ticks + event emission)
/// 3. History recorder (5s database snapshots + daily pruning)
/// 4. Tray updater (2s tooltip/menu + threshold notifications)
/// 5. Persistent-rules applier (3s auto-apply to new processes)
pub struct BackgroundServices;

impl BackgroundServices {
    /// Start all background services in the correct dependency order.
    pub fn start(
        process_mapper: &Arc<ProcessMapper>,
        traffic_tracker: &Arc<TrafficTracker>,
        rate_limiter: &Arc<RateLimiterManager>,
        database: &Arc<db::Database>,
        notification_threshold: &Arc<AtomicU64>,
        persistent_rules: &Arc<Mutex<Vec<db::SavedRule>>>,
        app_handle: tauri::AppHandle,
    ) {
        // 1. Process scanner — must start first so port-PID map is populated.
        process_mapper.start_scanning();

        // 2. Stats aggregator — depends on process_mapper for connection counts.
        traffic_tracker.start_aggregator(Arc::clone(process_mapper), app_handle.clone());

        // 3. History recorder — depends on traffic_tracker snapshots.
        Self::start_history_recorder(
            Arc::clone(traffic_tracker),
            Arc::clone(process_mapper),
            Arc::clone(database),
        );

        // 4. Tray updater — depends on traffic_tracker snapshots.
        Self::start_tray_updater(
            Arc::clone(traffic_tracker),
            Arc::clone(process_mapper),
            Arc::clone(notification_threshold),
            app_handle,
        );

        // 5. Persistent-rules applier — depends on traffic_tracker + rate_limiter.
        Self::start_persistent_rules_applier(
            Arc::clone(traffic_tracker),
            Arc::clone(process_mapper),
            Arc::clone(rate_limiter),
            Arc::clone(persistent_rules),
        );
    }

    fn start_history_recorder(
        tracker: Arc<TrafficTracker>,
        mapper: Arc<ProcessMapper>,
        db: Arc<db::Database>,
    ) {
        std::thread::Builder::new()
            .name("history-recorder".into())
            .spawn(move || {
                let mut prune_counter = 0u64;
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(
                        config::HISTORY_RECORD_INTERVAL_SECS,
                    ));
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

    fn start_tray_updater(
        tracker: Arc<TrafficTracker>,
        mapper: Arc<ProcessMapper>,
        threshold: Arc<AtomicU64>,
        handle: tauri::AppHandle,
    ) {
        std::thread::Builder::new()
            .name("tray-updater".into())
            .spawn(move || {
                let mut notified_pids: HashSet<u32> = HashSet::new();
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(
                        config::TRAY_UPDATE_INTERVAL_SECS,
                    ));
                    update_tray_and_notify(&handle, &tracker, &mapper, &threshold, &mut notified_pids);
                }
            })
            .expect("failed to spawn tray updater thread");
    }

    fn start_persistent_rules_applier(
        tracker: Arc<TrafficTracker>,
        mapper: Arc<ProcessMapper>,
        limiter: Arc<RateLimiterManager>,
        rules: Arc<Mutex<Vec<db::SavedRule>>>,
    ) {
        std::thread::Builder::new()
            .name("persistent-rules".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(
                    config::PERSISTENT_RULES_INTERVAL_SECS,
                ));
                apply_persistent_rules(&tracker, &mapper, &limiter, &rules);
            })
            .expect("failed to spawn persistent rules thread");
    }
}

// ===========================================================================
// Helper functions (moved from lib.rs)
// ===========================================================================

/// Update tray tooltip/menu and check bandwidth threshold notifications.
pub fn update_tray_and_notify(
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

    let threshold_bps = threshold.load(Ordering::Relaxed);
    if threshold_bps > 0 {
        for proc in &snapshot {
            let total_speed = proc.download_speed + proc.upload_speed;
            if total_speed as u64 > threshold_bps {
                if notified_pids.insert(proc.pid) {
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
                notified_pids.remove(&proc.pid);
            }
        }
    }
}

/// Apply persistent rules to running processes (F7, AC-7.2, AC-7.3).
pub fn apply_persistent_rules(
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
                if rule.blocked && !limiter.is_blocked(proc.pid) {
                    limiter.block_process(proc.pid);
                    tracing::debug!("Auto-applied block to {} (PID {})", proc.name, proc.pid);
                } else if (rule.download_bps > 0 || rule.upload_bps > 0)
                    && !limiter.is_limited(proc.pid)
                {
                    limiter.set_limit(
                        proc.pid,
                        BandwidthLimit {
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
pub fn build_tray_menu(
    app: &tauri::AppHandle,
    top_consumers: &[ProcessTrafficSnapshot],
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

    menu.append(&MenuItem::with_id(app, "show", "Show NetGuard", true, None::<&str>)?)?;
    menu.append(&MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?)?;

    Ok(menu)
}

/// Format a speed value in a compact human-readable form.
pub fn format_speed_compact(bps: f64) -> String {
    if bps < 1024.0 {
        format!("{:.0} B/s", bps)
    } else if bps < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", bps / 1024.0)
    } else {
        format!("{:.2} MB/s", bps / (1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_speed_compact_bytes() {
        assert_eq!(format_speed_compact(0.0), "0 B/s");
        assert_eq!(format_speed_compact(512.0), "512 B/s");
        assert_eq!(format_speed_compact(1023.0), "1023 B/s");
    }

    #[test]
    fn test_format_speed_compact_kilobytes() {
        assert_eq!(format_speed_compact(1024.0), "1.0 KB/s");
        assert_eq!(format_speed_compact(1536.0), "1.5 KB/s");
    }

    #[test]
    fn test_format_speed_compact_megabytes() {
        assert_eq!(format_speed_compact(1048576.0), "1.00 MB/s");
        assert_eq!(format_speed_compact(2621440.0), "2.50 MB/s");
    }
}
