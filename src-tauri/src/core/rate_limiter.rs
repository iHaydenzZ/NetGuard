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
