//! Token Bucket rate limiter for per-process bandwidth control.
//!
//! Each rate-limited process gets independent upload and download buckets.
//! Burst allowance is 2x the configured rate. Uses tokio timers for precise delays.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Bandwidth limit configuration for a single process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthLimit {
    /// Download limit in bytes per second (0 = unlimited).
    pub download_bps: u64,
    /// Upload limit in bytes per second (0 = unlimited).
    pub upload_bps: u64,
}

/// Per-direction token bucket state.
#[derive(Debug)]
struct TokenBucket {
    /// Configured rate in bytes/sec.
    rate_bps: u64,
    /// Current token count.
    tokens: f64,
    /// Maximum burst (2x rate as per PRD).
    max_tokens: f64,
    /// Last refill timestamp.
    last_refill: std::time::Instant,
}

impl TokenBucket {
    fn new(rate_bps: u64) -> Self {
        let max_tokens = (rate_bps * 2) as f64;
        Self {
            rate_bps,
            tokens: max_tokens, // start full
            max_tokens,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time, then try to consume `bytes`.
    /// Returns the delay (in milliseconds) the caller should wait before
    /// sending the packet. Returns 0 if tokens are available immediately.
    fn consume(&mut self, bytes: u64) -> u64 {
        if self.rate_bps == 0 {
            return 0; // unlimited
        }

        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        // Refill tokens
        self.tokens = (self.tokens + elapsed * self.rate_bps as f64).min(self.max_tokens);

        // Try to consume
        self.tokens -= bytes as f64;
        if self.tokens >= 0.0 {
            0 // immediate pass
        } else {
            // Compute delay to wait for tokens to become available
            let deficit = -self.tokens;
            let delay_secs = deficit / self.rate_bps as f64;
            (delay_secs * 1000.0).ceil() as u64
        }
    }

    /// Check if `bytes` can be consumed without exceeding the rate.
    /// Returns true if the packet should pass, false if it should be dropped.
    /// Tokens are consumed on pass; on drop, the deficit is NOT accumulated
    /// (so future packets aren't penalized for drops).
    fn should_pass(&mut self, bytes: u64) -> bool {
        if self.rate_bps == 0 {
            return true; // unlimited
        }

        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        // Refill tokens
        self.tokens = (self.tokens + elapsed * self.rate_bps as f64).min(self.max_tokens);

        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            true // within budget — pass
        } else {
            false // over budget — drop (don't deduct, so no accumulated debt)
        }
    }

    fn update_rate(&mut self, new_rate_bps: u64) {
        self.rate_bps = new_rate_bps;
        self.max_tokens = (new_rate_bps * 2) as f64;
        self.tokens = self.tokens.min(self.max_tokens);
    }
}

/// Per-process limiter holding download and upload buckets.
#[derive(Debug)]
struct ProcessLimiter {
    download: TokenBucket,
    upload: TokenBucket,
}

/// Manages rate limits and blocking for all processes.
pub struct RateLimiterManager {
    limiters: Mutex<HashMap<u32, ProcessLimiter>>,
    limits_config: Mutex<HashMap<u32, BandwidthLimit>>,
    /// Set of PIDs whose traffic should be silently dropped.
    blocked_pids: Mutex<std::collections::HashSet<u32>>,
}

impl RateLimiterManager {
    pub fn new() -> Self {
        Self {
            limiters: Mutex::new(HashMap::new()),
            limits_config: Mutex::new(HashMap::new()),
            blocked_pids: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Set a bandwidth limit for a process.
    pub fn set_limit(&self, pid: u32, limit: BandwidthLimit) {
        let mut limiters = self.limiters.lock().unwrap();
        let entry = limiters.entry(pid).or_insert_with(|| ProcessLimiter {
            download: TokenBucket::new(limit.download_bps),
            upload: TokenBucket::new(limit.upload_bps),
        });
        entry.download.update_rate(limit.download_bps);
        entry.upload.update_rate(limit.upload_bps);
        self.limits_config.lock().unwrap().insert(pid, limit);
    }

    /// Remove the bandwidth limit for a process.
    pub fn remove_limit(&self, pid: u32) {
        self.limiters.lock().unwrap().remove(&pid);
        self.limits_config.lock().unwrap().remove(&pid);
    }

    /// Check if a process has any rate limit configured.
    pub fn is_limited(&self, pid: u32) -> bool {
        self.limits_config.lock().unwrap().contains_key(&pid)
    }

    /// Get all current limit configurations.
    pub fn get_all_limits(&self) -> HashMap<u32, BandwidthLimit> {
        self.limits_config.lock().unwrap().clone()
    }

    /// Consume tokens for a packet. Returns delay in ms to wait before sending.
    /// Returns 0 if no limit is set or tokens are available.
    pub fn consume(&self, pid: u32, bytes: u64, is_upload: bool) -> u64 {
        let mut limiters = self.limiters.lock().unwrap();
        let Some(limiter) = limiters.get_mut(&pid) else {
            return 0;
        };

        if is_upload {
            limiter.upload.consume(bytes)
        } else {
            limiter.download.consume(bytes)
        }
    }

    /// Decide whether a packet should pass or be dropped (policer mode).
    /// Returns true if within rate budget or no limit is set.
    /// Returns false if rate limit exceeded (packet should be dropped).
    /// Blocked PIDs always return false.
    pub fn should_pass_packet(&self, pid: u32, bytes: u64, is_upload: bool) -> bool {
        // Check blocked first.
        if self.blocked_pids.lock().unwrap().contains(&pid) {
            return false;
        }

        let mut limiters = self.limiters.lock().unwrap();
        let Some(limiter) = limiters.get_mut(&pid) else {
            return true; // no limit → pass
        };

        if is_upload {
            limiter.upload.should_pass(bytes)
        } else {
            limiter.download.should_pass(bytes)
        }
    }

    /// Block all network traffic for a process.
    pub fn block_process(&self, pid: u32) {
        self.blocked_pids.lock().unwrap().insert(pid);
    }

    /// Unblock a process, restoring network access.
    pub fn unblock_process(&self, pid: u32) {
        self.blocked_pids.lock().unwrap().remove(&pid);
    }

    /// Check if a process is blocked.
    pub fn is_blocked(&self, pid: u32) -> bool {
        self.blocked_pids.lock().unwrap().contains(&pid)
    }

    /// Get all blocked PIDs.
    pub fn get_blocked_pids(&self) -> Vec<u32> {
        self.blocked_pids.lock().unwrap().iter().copied().collect()
    }

    /// Clear all limits and blocks (used when switching profiles).
    pub fn clear_all(&self) {
        self.limiters.lock().unwrap().clear();
        self.limits_config.lock().unwrap().clear();
        self.blocked_pids.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_new_manager_is_empty() {
        let mgr = RateLimiterManager::new();
        assert!(mgr.get_all_limits().is_empty(), "new manager should have no limits");
        assert!(mgr.get_blocked_pids().is_empty(), "new manager should have no blocks");
    }

    #[test]
    fn test_set_and_get_limit() {
        let mgr = RateLimiterManager::new();
        mgr.set_limit(100, BandwidthLimit { download_bps: 5000, upload_bps: 3000 });

        let limits = mgr.get_all_limits();
        assert_eq!(limits.len(), 1);
        let limit = limits.get(&100).expect("PID 100 should have a limit");
        assert_eq!(limit.download_bps, 5000);
        assert_eq!(limit.upload_bps, 3000);
    }

    #[test]
    fn test_remove_limit() {
        let mgr = RateLimiterManager::new();
        mgr.set_limit(100, BandwidthLimit { download_bps: 5000, upload_bps: 3000 });
        assert!(mgr.is_limited(100));

        mgr.remove_limit(100);
        assert!(!mgr.is_limited(100), "PID 100 should no longer be limited after removal");
        assert!(mgr.get_all_limits().is_empty());
    }

    #[test]
    fn test_is_limited() {
        let mgr = RateLimiterManager::new();
        assert!(!mgr.is_limited(100), "unlisted PID should not be limited");

        mgr.set_limit(100, BandwidthLimit { download_bps: 1000, upload_bps: 1000 });
        assert!(mgr.is_limited(100), "PID with set limit should be limited");

        mgr.remove_limit(100);
        assert!(!mgr.is_limited(100), "PID should not be limited after removal");
    }

    #[test]
    fn test_block_and_unblock() {
        let mgr = RateLimiterManager::new();
        assert!(!mgr.is_blocked(200), "PID should not be blocked initially");

        mgr.block_process(200);
        assert!(mgr.is_blocked(200), "PID 200 should be blocked after block_process");

        mgr.unblock_process(200);
        assert!(!mgr.is_blocked(200), "PID 200 should not be blocked after unblock");
    }

    #[test]
    fn test_get_blocked_pids() {
        let mgr = RateLimiterManager::new();
        mgr.block_process(10);
        mgr.block_process(20);
        mgr.block_process(30);

        let mut blocked = mgr.get_blocked_pids();
        blocked.sort();
        assert_eq!(blocked, vec![10, 20, 30]);
    }

    #[test]
    fn test_clear_all() {
        let mgr = RateLimiterManager::new();
        mgr.set_limit(1, BandwidthLimit { download_bps: 1000, upload_bps: 500 });
        mgr.set_limit(2, BandwidthLimit { download_bps: 2000, upload_bps: 1000 });
        mgr.block_process(3);
        mgr.block_process(4);

        mgr.clear_all();

        assert!(mgr.get_all_limits().is_empty(), "limits should be empty after clear_all");
        assert!(mgr.get_blocked_pids().is_empty(), "blocked pids should be empty after clear_all");
        assert!(!mgr.is_limited(1));
        assert!(!mgr.is_blocked(3));
    }

    #[test]
    fn test_consume_no_limit_returns_zero() {
        let mgr = RateLimiterManager::new();
        // PID 999 has no limit set
        let delay = mgr.consume(999, 10_000, false);
        assert_eq!(delay, 0, "consume for unmanaged PID should return 0 delay");
    }

    #[test]
    fn test_consume_within_burst_returns_zero() {
        let mgr = RateLimiterManager::new();
        // Large limit: 1 MB/s → burst capacity is 2 MB
        mgr.set_limit(100, BandwidthLimit { download_bps: 1_000_000, upload_bps: 1_000_000 });

        // Consume a small amount well within burst capacity
        let delay = mgr.consume(100, 500, false);
        assert_eq!(delay, 0, "small consume within burst should return 0 delay");
    }

    #[test]
    fn test_consume_exceeding_tokens_returns_delay() {
        let mgr = RateLimiterManager::new();
        // Small rate: 1000 bytes/sec → burst capacity = 2000 tokens
        mgr.set_limit(100, BandwidthLimit { download_bps: 1000, upload_bps: 1000 });

        // Consume more than the burst capacity to guarantee a deficit
        let delay = mgr.consume(100, 5000, false);
        assert!(delay > 0, "consuming 5000 bytes with 1000 bps rate (2000 burst) should return non-zero delay");
    }

    #[test]
    fn test_consume_upload_and_download_independent() {
        let mgr = RateLimiterManager::new();
        // Rate: 1000 bps → burst = 2000 tokens per direction
        mgr.set_limit(100, BandwidthLimit { download_bps: 1000, upload_bps: 1000 });

        // Exhaust download tokens
        let dl_delay = mgr.consume(100, 5000, false);
        assert!(dl_delay > 0, "download bucket should be exhausted");

        // Upload bucket should still be full, so small consume returns 0
        let ul_delay = mgr.consume(100, 500, true);
        assert_eq!(ul_delay, 0, "upload bucket should be independent and still have tokens");
    }

    #[test]
    fn test_update_rate_via_set_limit() {
        let mgr = RateLimiterManager::new();
        mgr.set_limit(100, BandwidthLimit { download_bps: 1000, upload_bps: 500 });

        let limits_v1 = mgr.get_all_limits();
        assert_eq!(limits_v1.get(&100).unwrap().download_bps, 1000);

        // Update with new rates
        mgr.set_limit(100, BandwidthLimit { download_bps: 5000, upload_bps: 2500 });

        let limits_v2 = mgr.get_all_limits();
        let limit = limits_v2.get(&100).unwrap();
        assert_eq!(limit.download_bps, 5000, "download rate should be updated");
        assert_eq!(limit.upload_bps, 2500, "upload rate should be updated");
        assert_eq!(limits_v2.len(), 1, "should still have only one entry for PID 100");
    }

    #[test]
    fn test_token_bucket_refills_over_time() {
        let mgr = RateLimiterManager::new();
        // Rate: 10000 bytes/sec → burst = 20000 tokens
        mgr.set_limit(100, BandwidthLimit { download_bps: 10_000, upload_bps: 10_000 });

        // Drain the bucket exactly to zero (burst capacity = 20000)
        let first_delay = mgr.consume(100, 20_000, false);
        assert_eq!(first_delay, 0, "first consume should use all burst tokens with zero delay");

        // Bucket is now at 0; consuming anything should produce a delay
        let second_delay = mgr.consume(100, 1_000, false);
        assert!(second_delay > 0, "second consume should return delay when bucket is empty");
        // At this point tokens are at -1000

        // Wait 200ms → at 10000 bps, ~2000 tokens should refill → bucket ~+1000
        sleep(Duration::from_millis(200));

        // Consume a small amount that fits within the refilled tokens
        let third_delay = mgr.consume(100, 500, false);
        assert_eq!(third_delay, 0, "after sleeping 200ms, small consume should succeed without delay");
    }

    // --- should_pass_packet (policer mode) tests ---

    #[test]
    fn test_should_pass_no_limit() {
        let mgr = RateLimiterManager::new();
        // PID 999 has no limit
        assert!(mgr.should_pass_packet(999, 10_000, false), "unmanaged PID should always pass");
    }

    #[test]
    fn test_should_pass_within_budget() {
        let mgr = RateLimiterManager::new();
        mgr.set_limit(100, BandwidthLimit { download_bps: 1_000_000, upload_bps: 1_000_000 });

        // Small packet well within burst (2MB)
        assert!(mgr.should_pass_packet(100, 500, false), "small packet should pass");
    }

    #[test]
    fn test_should_drop_over_budget() {
        let mgr = RateLimiterManager::new();
        // Rate: 1000 bps → burst = 2000 tokens
        mgr.set_limit(100, BandwidthLimit { download_bps: 1000, upload_bps: 1000 });

        // Exhaust the burst budget
        assert!(mgr.should_pass_packet(100, 1500, false), "first 1500 bytes should pass");
        assert!(mgr.should_pass_packet(100, 400, false), "next 400 bytes should pass (still within 2000)");
        // Now ~100 tokens left, 500-byte packet should be dropped
        assert!(!mgr.should_pass_packet(100, 500, false), "over-budget packet should be dropped");
    }

    #[test]
    fn test_should_drop_blocked_pid() {
        let mgr = RateLimiterManager::new();
        mgr.block_process(200);
        assert!(!mgr.should_pass_packet(200, 100, false), "blocked PID should be dropped");
        assert!(!mgr.should_pass_packet(200, 100, true), "blocked PID upload should be dropped");
    }

    #[test]
    fn test_should_pass_refills_after_drop() {
        let mgr = RateLimiterManager::new();
        // Rate: 10000 bps → burst = 20000 tokens
        mgr.set_limit(100, BandwidthLimit { download_bps: 10_000, upload_bps: 10_000 });

        // Exhaust tokens
        assert!(mgr.should_pass_packet(100, 20_000, false));
        // Over budget
        assert!(!mgr.should_pass_packet(100, 1_000, false));

        // Wait for tokens to refill (~2000 tokens in 200ms at 10000 bps)
        sleep(Duration::from_millis(200));

        // Small packet should pass again
        assert!(mgr.should_pass_packet(100, 500, false), "should pass after token refill");
    }
}
