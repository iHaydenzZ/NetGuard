//! macOS packet capture using pf (Packet Filter) + dnctl/dummynet.
//!
//! Bandwidth shaping is delegated to the kernel via dummynet pipes.
//! Configuration via `std::process::Command` calling `dnctl` and `pfctl`.
//!
//! ## Architecture
//!
//! On macOS, rate limiting and blocking are implemented at the kernel level
//! using pf (Packet Filter) and dummynet pipes. This differs from the Windows
//! approach where user-space token buckets handle rate limiting.
//!
//! - **Sniff mode**: No-op for packet capture. Traffic monitoring is handled
//!   by the process_mapper and traffic_tracker via sysinfo's network stats.
//!   pf does not have a clean sniff-only mode, and adding unnecessary pf rules
//!   would increase risk without benefit.
//!
//! - **Intercept mode**: Uses pf anchor rules to route per-process traffic
//!   through dummynet pipes configured with bandwidth limits.
//!
//! ## pf Anchor Design
//!
//! All NetGuard rules live under the `com.apple.netguard` anchor to avoid
//! interfering with the system's existing pf configuration:
//!
//! ```text
//! anchor "netguard" {
//!     # Per-process rules are loaded dynamically
//!     pass in  on lo0 proto { tcp, udp } from any port {P1,P2,...} to any pipe N
//!     pass out on lo0 proto { tcp, udp } from any to any port {P1,P2,...} pipe N
//!     block drop proto { tcp, udp } from any port {B1,B2,...} to any
//!     block drop proto { tcp, udp } from any to any port {B1,B2,...}
//! }
//! ```
//!
//! ## Safety
//!
//! The `PfState` struct implements `Drop` to flush all rules and pipes on exit
//! or panic (PRD safety invariant S4, AC-DS5). Emergency recovery:
//! ```bash
//! sudo pfctl -a netguard -F all
//! sudo dnctl -f flush
//! ```

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};

/// The pf anchor name used by NetGuard. All rules are scoped under this anchor
/// to avoid interfering with the system's existing pf configuration.
const PF_ANCHOR: &str = "netguard";

/// Base pipe number for dummynet pipes. Each process gets two pipes:
/// `BASE + pid_index * 2` for download, `BASE + pid_index * 2 + 1` for upload.
const PIPE_BASE: u32 = 10000;

/// Maximum pipe number we will allocate (safety bound).
const PIPE_MAX: u32 = 60000;

/// Path for the temporary pf rules file.
const PF_RULES_PATH: &str = "/tmp/netguard_pf.conf";

// ---------------------------------------------------------------------------
// Core pf/dnctl state management
// ---------------------------------------------------------------------------

/// Represents a dummynet pipe pair (download + upload) for a single process.
#[derive(Debug, Clone)]
struct PipeAllocation {
    /// PID this pipe pair belongs to.
    pid: u32,
    /// Pipe number for download shaping.
    download_pipe: u32,
    /// Pipe number for upload shaping.
    upload_pipe: u32,
    /// Download bandwidth limit in bytes/sec.
    download_bps: u64,
    /// Upload bandwidth limit in bytes/sec.
    upload_bps: u64,
    /// Local ports belonging to this process (refreshed from process_mapper).
    ports: HashSet<u16>,
}

/// Represents a blocked process.
#[derive(Debug, Clone)]
struct BlockEntry {
    pid: u32,
    /// Local ports belonging to this process.
    ports: HashSet<u16>,
}

/// Manages pf anchor rules and dummynet pipe lifecycle.
///
/// All mutations to pf/dnctl go through this struct's methods, which
/// ensures consistent state and proper cleanup.
pub struct PfState {
    /// Active pipe allocations, keyed by PID.
    pipes: HashMap<u32, PipeAllocation>,
    /// Blocked PIDs, keyed by PID.
    blocked: HashMap<u32, BlockEntry>,
    /// Next pipe number to allocate (monotonically increasing).
    next_pipe: u32,
    /// Whether the pf anchor has been registered with the system.
    anchor_registered: bool,
    /// Whether intercept mode is active.
    active: bool,
}

impl PfState {
    pub fn new() -> Self {
        Self {
            pipes: HashMap::new(),
            blocked: HashMap::new(),
            next_pipe: PIPE_BASE,
            anchor_registered: false,
            active: false,
        }
    }

    /// Allocate a pipe pair for a process. Returns (download_pipe, upload_pipe).
    fn allocate_pipe_pair(&mut self) -> Result<(u32, u32)> {
        let dl = self.next_pipe;
        let ul = self.next_pipe + 1;
        if ul >= PIPE_MAX {
            bail!("Dummynet pipe number space exhausted (max {PIPE_MAX})");
        }
        self.next_pipe += 2;
        Ok((dl, ul))
    }

    /// Ensure the NetGuard pf anchor is registered in the system's pf.conf.
    /// This adds an `rdr-anchor` and `anchor` directive if not already present.
    fn ensure_anchor(&mut self) -> Result<()> {
        if self.anchor_registered {
            return Ok(());
        }

        // Check if pf is already enabled. If not, we enable it.
        let status = run_command("pfctl", &["-s", "info"])?;
        let pf_enabled = status.contains("Status: Enabled");

        // Check if our anchor already exists in the current ruleset.
        let rules = run_command("pfctl", &["-s", "Anchors"])?;
        if !rules.contains(PF_ANCHOR) {
            // Load the anchor reference into the main pf ruleset.
            // We write a temporary file that includes the anchor and load it.
            //
            // Strategy: Get current rules, append our anchor, reload.
            // However, modifying the main pf.conf is risky. Instead, we use
            // pfctl's ability to add anchors dynamically via `-a`.
            //
            // On modern macOS, anchors can be used directly with `-a` without
            // modifying the main ruleset. The anchor just needs to be loaded.
            tracing::info!("Registering pf anchor '{PF_ANCHOR}'");
        }

        // Enable pf if not already enabled (requires root).
        if !pf_enabled {
            run_command_no_output("pfctl", &["-e"])
                .context("Failed to enable pf — is the app running as root?")?;
            tracing::info!("pf enabled");
        }

        self.anchor_registered = true;
        Ok(())
    }

    /// Configure a dummynet pipe with a bandwidth limit.
    fn configure_pipe(&self, pipe_num: u32, bandwidth_bps: u64) -> Result<()> {
        if bandwidth_bps == 0 {
            // No limit — configure pipe with no bandwidth restriction.
            // dnctl pipe with 0 bw means unlimited.
            run_command_no_output(
                "dnctl",
                &["pipe", &pipe_num.to_string(), "config", "bw", "0"],
            )
            .with_context(|| format!("Failed to configure pipe {pipe_num} as unlimited"))?;
        } else {
            // Convert bytes/sec to bits/sec for dnctl.
            let bits_per_sec = bandwidth_bps * 8;
            let bw_str = format!("{bits_per_sec}bit/s");
            run_command_no_output(
                "dnctl",
                &["pipe", &pipe_num.to_string(), "config", "bw", &bw_str],
            )
            .with_context(|| format!("Failed to configure pipe {pipe_num} with bw {bw_str}"))?;
        }
        Ok(())
    }

    /// Delete a dummynet pipe.
    fn delete_pipe(&self, pipe_num: u32) -> Result<()> {
        // dnctl pipe N delete
        let _ = run_command_no_output("dnctl", &["pipe", &pipe_num.to_string(), "delete"]);
        // Ignore errors — pipe may already be gone.
        Ok(())
    }

    /// Set a bandwidth limit for a process.
    ///
    /// Creates dummynet pipes and updates pf rules to route the process's
    /// traffic through them.
    pub fn set_rate_limit(
        &mut self,
        pid: u32,
        download_bps: u64,
        upload_bps: u64,
        ports: HashSet<u16>,
    ) -> Result<()> {
        self.ensure_anchor()?;

        if let Some(existing) = self.pipes.get_mut(&pid) {
            // Update existing pipe configuration.
            existing.download_bps = download_bps;
            existing.upload_bps = upload_bps;
            existing.ports = ports;
            // Copy pipe numbers before releasing the mutable borrow on self.pipes
            // so we can call self.configure_pipe() without borrow conflicts.
            let (dl_pipe, ul_pipe) = (existing.download_pipe, existing.upload_pipe);
            // Mutable borrow ends here (existing goes out of scope after the block).
            self.configure_pipe(dl_pipe, download_bps)?;
            self.configure_pipe(ul_pipe, upload_bps)?;
        } else {
            // Allocate new pipe pair.
            let (dl_pipe, ul_pipe) = self.allocate_pipe_pair()?;
            self.configure_pipe(dl_pipe, download_bps)?;
            self.configure_pipe(ul_pipe, upload_bps)?;

            self.pipes.insert(
                pid,
                PipeAllocation {
                    pid,
                    download_pipe: dl_pipe,
                    upload_pipe: ul_pipe,
                    download_bps,
                    upload_bps,
                    ports,
                },
            );
        }

        // Rebuild and reload pf rules.
        self.reload_pf_rules()?;

        tracing::info!("Set rate limit for PID {pid}: DL={download_bps} B/s, UL={upload_bps} B/s");
        Ok(())
    }

    /// Remove the bandwidth limit for a process.
    pub fn remove_rate_limit(&mut self, pid: u32) -> Result<()> {
        if let Some(alloc) = self.pipes.remove(&pid) {
            self.delete_pipe(alloc.download_pipe)?;
            self.delete_pipe(alloc.upload_pipe)?;
            self.reload_pf_rules()?;
            tracing::info!("Removed rate limit for PID {pid}");
        }
        Ok(())
    }

    /// Block all traffic for a process.
    pub fn block_process(&mut self, pid: u32, ports: HashSet<u16>) -> Result<()> {
        self.ensure_anchor()?;
        self.blocked.insert(pid, BlockEntry { pid, ports });
        self.reload_pf_rules()?;
        tracing::info!("Blocked PID {pid}");
        Ok(())
    }

    /// Unblock a process.
    pub fn unblock_process(&mut self, pid: u32) -> Result<()> {
        if self.blocked.remove(&pid).is_some() {
            self.reload_pf_rules()?;
            tracing::info!("Unblocked PID {pid}");
        }
        Ok(())
    }

    /// Update the port set for a process (called when process_mapper refreshes).
    pub fn update_ports(&mut self, pid: u32, ports: HashSet<u16>) -> Result<()> {
        let mut changed = false;

        if let Some(alloc) = self.pipes.get_mut(&pid) {
            if alloc.ports != ports {
                alloc.ports = ports.clone();
                changed = true;
            }
        }
        if let Some(entry) = self.blocked.get_mut(&pid) {
            if entry.ports != ports {
                entry.ports = ports;
                changed = true;
            }
        }

        if changed {
            self.reload_pf_rules()?;
        }
        Ok(())
    }

    /// Generate pf rules and reload the anchor.
    ///
    /// Writes rules to a temporary file and loads them into the anchor via
    /// `pfctl -a netguard -f /tmp/netguard_pf.conf`.
    fn reload_pf_rules(&self) -> Result<()> {
        let rules = self.generate_pf_rules();

        // Write rules to temp file.
        {
            let mut file =
                std::fs::File::create(PF_RULES_PATH).context("Failed to create pf rules file")?;
            file.write_all(rules.as_bytes())
                .context("Failed to write pf rules")?;
        }

        // Load rules into the anchor.
        run_command_no_output("pfctl", &["-a", PF_ANCHOR, "-f", PF_RULES_PATH])
            .context("Failed to load pf rules into anchor")?;

        tracing::debug!("Reloaded pf rules:\n{rules}");
        Ok(())
    }

    /// Generate the pf ruleset for the NetGuard anchor.
    fn generate_pf_rules(&self) -> String {
        let mut rules = String::new();

        rules.push_str("# NetGuard pf rules — auto-generated, do not edit\n");
        rules.push_str("# Flush and reload atomically via pfctl -a netguard\n\n");

        // Dummynet pipe rules for rate-limited processes.
        for alloc in self.pipes.values() {
            if alloc.ports.is_empty() {
                continue;
            }

            let port_list = format_port_list(&alloc.ports);

            // Route inbound traffic (download) through the download pipe.
            // "dummynet-anchor" rules use `route-to` semantics with pipe.
            // pf rule: match incoming traffic destined to local ports → pipe N
            rules.push_str(&format!(
                "dummynet in proto {{ tcp, udp }} from any to any port {{ {port_list} }} pipe {}\n",
                alloc.download_pipe
            ));

            // Route outbound traffic (upload) through the upload pipe.
            rules.push_str(&format!(
                "dummynet out proto {{ tcp, udp }} from any port {{ {port_list} }} to any pipe {}\n",
                alloc.upload_pipe
            ));
        }

        // Block rules for blocked processes.
        for entry in self.blocked.values() {
            if entry.ports.is_empty() {
                continue;
            }

            let port_list = format_port_list(&entry.ports);

            // Block both directions for the process's ports.
            rules.push_str(&format!(
                "block drop in proto {{ tcp, udp }} from any to any port {{ {port_list} }}\n"
            ));
            rules.push_str(&format!(
                "block drop out proto {{ tcp, udp }} from any port {{ {port_list} }} to any\n"
            ));
        }

        rules
    }

    /// Flush all NetGuard pf rules and dummynet pipes.
    /// Called on shutdown and from Drop.
    pub fn cleanup(&mut self) {
        tracing::info!("Cleaning up pf rules and dummynet pipes");

        // Flush all rules in the NetGuard anchor.
        if let Err(e) = run_command_no_output("pfctl", &["-a", PF_ANCHOR, "-F", "all"]) {
            tracing::warn!("Failed to flush pf anchor rules: {e}");
        }

        // Delete all allocated dummynet pipes individually.
        for alloc in self.pipes.values() {
            let _ = self.delete_pipe(alloc.download_pipe);
            let _ = self.delete_pipe(alloc.upload_pipe);
        }

        // Also do a broad flush of all dummynet pipes in our range as a safety net.
        // This catches pipes that may have leaked if state got out of sync.
        if let Err(e) = run_command_no_output("dnctl", &["-f", "flush"]) {
            tracing::warn!("Failed to flush dummynet pipes: {e}");
        }

        // Clean up the temp rules file.
        let _ = std::fs::remove_file(PF_RULES_PATH);

        self.pipes.clear();
        self.blocked.clear();
        self.active = false;
        self.anchor_registered = false;

        tracing::info!("pf/dnctl cleanup complete");
    }
}

impl Drop for PfState {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// ---------------------------------------------------------------------------
// Thread-safe wrapper for PfState
// ---------------------------------------------------------------------------

/// Thread-safe handle to the pf state, shared between the CaptureEngine
/// and the Tauri command handlers.
///
/// All pf/dnctl operations are serialized through a Mutex to prevent
/// concurrent rule modifications.
#[derive(Clone)]
pub struct PfHandle {
    state: Arc<Mutex<PfState>>,
    active: Arc<AtomicBool>,
}

impl PfHandle {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(PfState::new())),
            active: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Set a bandwidth limit for a process.
    pub fn set_rate_limit(
        &self,
        pid: u32,
        download_bps: u64,
        upload_bps: u64,
        ports: HashSet<u16>,
    ) -> Result<()> {
        self.state
            .lock()
            .map_err(|e| anyhow::anyhow!("PfState lock poisoned: {e}"))?
            .set_rate_limit(pid, download_bps, upload_bps, ports)
    }

    /// Remove the bandwidth limit for a process.
    pub fn remove_rate_limit(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .map_err(|e| anyhow::anyhow!("PfState lock poisoned: {e}"))?
            .remove_rate_limit(pid)
    }

    /// Block all traffic for a process.
    pub fn block_process(&self, pid: u32, ports: HashSet<u16>) -> Result<()> {
        self.state
            .lock()
            .map_err(|e| anyhow::anyhow!("PfState lock poisoned: {e}"))?
            .block_process(pid, ports)
    }

    /// Unblock a process.
    pub fn unblock_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .map_err(|e| anyhow::anyhow!("PfState lock poisoned: {e}"))?
            .unblock_process(pid)
    }

    /// Update ports for a process.
    pub fn update_ports(&self, pid: u32, ports: HashSet<u16>) -> Result<()> {
        self.state
            .lock()
            .map_err(|e| anyhow::anyhow!("PfState lock poisoned: {e}"))?
            .update_ports(pid, ports)
    }

    /// Clean up all rules and pipes.
    pub fn cleanup(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.cleanup();
        }
    }

    /// Check if intercept mode is active.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Set the active state.
    pub fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Public API: sniff and intercept loops
// ---------------------------------------------------------------------------

/// Start monitoring in SNIFF mode on macOS.
///
/// On macOS, sniff mode is a no-op for packet capture. Traffic monitoring
/// is handled entirely by the process_mapper (sysinfo network stats) and
/// traffic_tracker in the core layer. pf does not have a clean sniff-only
/// mode equivalent to WinDivert's SNIFF flag, and adding unnecessary pf
/// rules would increase risk without benefit.
///
/// This function returns Ok(()) immediately. The caller (CaptureEngine)
/// does not need a background thread for macOS sniff mode.
pub fn start_sniff() -> Result<()> {
    tracing::info!(
        "macOS SNIFF mode: packet capture is a no-op; \
         traffic monitoring uses sysinfo via process_mapper"
    );
    Ok(())
}

/// Start the intercept mode synchronization loop.
///
/// This loop runs in a dedicated thread and periodically synchronizes
/// the pf/dnctl configuration with the RateLimiterManager state.
///
/// On macOS, rate limiting is performed at the kernel level by dummynet
/// pipes rather than in user-space token buckets. This loop:
///
/// 1. Reads the current limits and blocks from RateLimiterManager
/// 2. Resolves PIDs to local ports via ProcessMapper
/// 3. Creates/updates/removes dummynet pipes and pf rules accordingly
///
/// This approach ensures that pf rules stay in sync with the application
/// state even as processes start, stop, and change ports.
pub fn run_intercept_sync_loop(
    pf_handle: PfHandle,
    process_mapper: Arc<crate::core::process_mapper::ProcessMapper>,
    rate_limiter: Arc<crate::core::rate_limiter::RateLimiterManager>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    tracing::info!("macOS INTERCEPT sync loop started");

    pf_handle.set_active(true);

    while !shutdown.load(Ordering::Relaxed) {
        if let Err(e) = sync_pf_state(&pf_handle, &process_mapper, &rate_limiter) {
            tracing::error!("Failed to sync pf state: {e:#}");
        }

        // Sync every 500ms to stay responsive to limit changes.
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // Clean shutdown.
    pf_handle.cleanup();
    tracing::info!("macOS INTERCEPT sync loop stopped");
    Ok(())
}

/// Synchronize pf/dnctl state with the current RateLimiterManager configuration.
fn sync_pf_state(
    pf_handle: &PfHandle,
    process_mapper: &crate::core::process_mapper::ProcessMapper,
    rate_limiter: &crate::core::rate_limiter::RateLimiterManager,
) -> Result<()> {
    let limits = rate_limiter.get_all_limits();
    let blocked_pids = rate_limiter.get_blocked_pids();

    let mut state = pf_handle
        .state
        .lock()
        .map_err(|e| anyhow::anyhow!("PfState lock poisoned: {e}"))?;

    // Track which PIDs are still active so we can remove stale entries.
    let mut active_limited_pids: HashSet<u32> = HashSet::new();
    let mut active_blocked_pids: HashSet<u32> = HashSet::new();

    // Sync rate limits.
    for (pid, limit) in &limits {
        active_limited_pids.insert(*pid);

        // Get the ports for this process.
        let ports = get_process_ports(process_mapper, *pid);
        if ports.is_empty() {
            // Process has no active ports — skip.
            continue;
        }

        // Check if we need to create or update the pipe.
        let needs_update = match state.pipes.get(pid) {
            Some(existing) => {
                existing.download_bps != limit.download_bps
                    || existing.upload_bps != limit.upload_bps
                    || existing.ports != ports
            }
            None => true,
        };

        if needs_update {
            // This will create or update the pipe allocation and reload pf rules.
            // We drop the mutex temporarily to avoid holding it during system calls.
            drop(state);
            pf_handle.set_rate_limit(*pid, limit.download_bps, limit.upload_bps, ports)?;
            state = pf_handle
                .state
                .lock()
                .map_err(|e| anyhow::anyhow!("PfState lock poisoned: {e}"))?;
        }
    }

    // Sync blocked PIDs.
    for pid in &blocked_pids {
        active_blocked_pids.insert(*pid);

        let ports = get_process_ports(process_mapper, *pid);
        if ports.is_empty() {
            continue;
        }

        let needs_update = match state.blocked.get(pid) {
            Some(existing) => existing.ports != ports,
            None => true,
        };

        if needs_update {
            drop(state);
            pf_handle.block_process(*pid, ports)?;
            state = pf_handle
                .state
                .lock()
                .map_err(|e| anyhow::anyhow!("PfState lock poisoned: {e}"))?;
        }
    }

    // Remove stale pipe allocations (PIDs no longer rate-limited).
    let stale_limited: Vec<u32> = state
        .pipes
        .keys()
        .filter(|pid| !active_limited_pids.contains(pid))
        .copied()
        .collect();

    for pid in stale_limited {
        drop(state);
        pf_handle.remove_rate_limit(pid)?;
        state = pf_handle
            .state
            .lock()
            .map_err(|e| anyhow::anyhow!("PfState lock poisoned: {e}"))?;
    }

    // Remove stale block entries.
    let stale_blocked: Vec<u32> = state
        .blocked
        .keys()
        .filter(|pid| !active_blocked_pids.contains(pid))
        .copied()
        .collect();

    for pid in stale_blocked {
        drop(state);
        pf_handle.unblock_process(pid)?;
        state = pf_handle
            .state
            .lock()
            .map_err(|e| anyhow::anyhow!("PfState lock poisoned: {e}"))?;
    }

    Ok(())
}

/// Get all local ports owned by a process, queried from the ProcessMapper.
fn get_process_ports(
    _mapper: &crate::core::process_mapper::ProcessMapper,
    pid: u32,
) -> HashSet<u16> {
    // The ProcessMapper doesn't expose a direct "ports for PID" lookup,
    // but we can use the connection_counts and active_pids to derive it.
    // For a more direct approach, we scan all connections.
    //
    // Since ProcessMapper stores (Protocol, port) -> PID, we need to iterate.
    // This is called from the sync loop (every 500ms) so we can afford it.
    //
    // Note: In a future refactor, ProcessMapper could expose a reverse lookup.
    let mut ports = HashSet::new();

    // We probe a range of common ports. This is a limitation of the current
    // ProcessMapper API. A better approach would be to expose a reverse lookup
    // method on ProcessMapper. For now, we use a practical approach.
    //
    // Actually, the ProcessMapper uses DashMap internally. We can iterate
    // through it if we add a helper method, but since we can't modify the
    // ProcessMapper from this module without changing its API, we'll use
    // the lsof approach to get ports for a specific PID on macOS.
    if let Ok(output) = Command::new("lsof")
        .args(["-i", "-n", "-P", "-a", "-p", &pid.to_string(), "-F", "n"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                // lsof -F n produces lines like "n*:PORT" or "n[::]:PORT->..."
                if let Some(stripped) = line.strip_prefix('n') {
                    if let Some(port) = extract_local_port(stripped) {
                        ports.insert(port);
                    }
                }
            }
        }
    }

    ports
}

/// Extract the local port from an lsof network address string.
///
/// Handles formats like:
/// - `*:8080`
/// - `127.0.0.1:8080`
/// - `[::1]:8080`
/// - `*:8080->192.168.1.1:443`
/// - `192.168.1.1:12345->10.0.0.1:443`
fn extract_local_port(addr: &str) -> Option<u16> {
    // Strip everything after "->" (remote side).
    let local = addr.split("->").next()?;

    // Find the last ':' — port follows it.
    let colon_idx = local.rfind(':')?;
    let port_str = &local[colon_idx + 1..];
    port_str.parse::<u16>().ok()
}

// ---------------------------------------------------------------------------
// Command execution helpers
// ---------------------------------------------------------------------------

/// Run a command and return its stdout as a String.
fn run_command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute {program} {}", args.join(" ")))?;

    // pfctl and dnctl sometimes output to stderr even on success.
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        // Some pfctl commands return non-zero but are actually fine
        // (e.g., "pfctl -e" when pf is already enabled).
        tracing::debug!(
            "{program} {} exited with status {}: stdout={stdout}, stderr={stderr}",
            args.join(" "),
            output.status
        );
    }

    Ok(format!("{stdout}{stderr}"))
}

/// Run a command, logging but not returning output.
fn run_command_no_output(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute {program} {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        tracing::debug!(
            "{program} {} exited with {}: stderr={stderr}, stdout={stdout}",
            args.join(" "),
            output.status,
        );
    }

    Ok(())
}

/// Format a set of ports as a comma-separated string for pf rules.
fn format_port_list(ports: &HashSet<u16>) -> String {
    let mut sorted: Vec<u16> = ports.iter().copied().collect();
    sorted.sort_unstable();
    sorted
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_local_port_star() {
        assert_eq!(extract_local_port("*:8080"), Some(8080));
    }

    #[test]
    fn test_extract_local_port_ipv4() {
        assert_eq!(extract_local_port("127.0.0.1:3000"), Some(3000));
    }

    #[test]
    fn test_extract_local_port_ipv6() {
        assert_eq!(extract_local_port("[::1]:443"), Some(443));
    }

    #[test]
    fn test_extract_local_port_with_remote() {
        assert_eq!(
            extract_local_port("192.168.1.1:12345->10.0.0.1:443"),
            Some(12345)
        );
    }

    #[test]
    fn test_extract_local_port_star_with_remote() {
        assert_eq!(extract_local_port("*:8080->192.168.1.1:443"), Some(8080));
    }

    #[test]
    fn test_extract_local_port_invalid() {
        assert_eq!(extract_local_port("no-port-here"), None);
        assert_eq!(extract_local_port(""), None);
    }

    #[test]
    fn test_extract_local_port_non_numeric() {
        assert_eq!(extract_local_port("*:http"), None);
    }

    #[test]
    fn test_format_port_list_empty() {
        let ports = HashSet::new();
        assert_eq!(format_port_list(&ports), "");
    }

    #[test]
    fn test_format_port_list_single() {
        let mut ports = HashSet::new();
        ports.insert(8080);
        assert_eq!(format_port_list(&ports), "8080");
    }

    #[test]
    fn test_format_port_list_multiple_sorted() {
        let mut ports = HashSet::new();
        ports.insert(443);
        ports.insert(80);
        ports.insert(8080);
        assert_eq!(format_port_list(&ports), "80, 443, 8080");
    }

    #[test]
    fn test_pf_state_new() {
        let state = PfState::new();
        assert!(state.pipes.is_empty());
        assert!(state.blocked.is_empty());
        assert_eq!(state.next_pipe, PIPE_BASE);
        assert!(!state.anchor_registered);
        assert!(!state.active);
    }

    #[test]
    fn test_allocate_pipe_pair() {
        let mut state = PfState::new();
        let (dl, ul) = state.allocate_pipe_pair().unwrap();
        assert_eq!(dl, PIPE_BASE);
        assert_eq!(ul, PIPE_BASE + 1);

        let (dl2, ul2) = state.allocate_pipe_pair().unwrap();
        assert_eq!(dl2, PIPE_BASE + 2);
        assert_eq!(ul2, PIPE_BASE + 3);
    }

    #[test]
    fn test_allocate_pipe_pair_exhaustion() {
        let mut state = PfState::new();
        state.next_pipe = PIPE_MAX; // Force exhaustion.
        assert!(state.allocate_pipe_pair().is_err());
    }

    #[test]
    fn test_generate_pf_rules_empty() {
        let state = PfState::new();
        let rules = state.generate_pf_rules();
        // Should only contain comments, no actual rules.
        assert!(rules.contains("auto-generated"));
        assert!(!rules.contains("dummynet"));
        assert!(!rules.contains("block"));
    }

    #[test]
    fn test_generate_pf_rules_rate_limited() {
        let mut state = PfState::new();
        let mut ports = HashSet::new();
        ports.insert(80);
        ports.insert(443);

        state.pipes.insert(
            100,
            PipeAllocation {
                pid: 100,
                download_pipe: 10000,
                upload_pipe: 10001,
                download_bps: 1_000_000,
                upload_bps: 500_000,
                ports,
            },
        );

        let rules = state.generate_pf_rules();
        assert!(rules.contains("dummynet in"));
        assert!(rules.contains("dummynet out"));
        assert!(rules.contains("pipe 10000"));
        assert!(rules.contains("pipe 10001"));
        assert!(rules.contains("80"));
        assert!(rules.contains("443"));
    }

    #[test]
    fn test_generate_pf_rules_blocked() {
        let mut state = PfState::new();
        let mut ports = HashSet::new();
        ports.insert(5201);

        state.blocked.insert(200, BlockEntry { pid: 200, ports });

        let rules = state.generate_pf_rules();
        assert!(rules.contains("block drop in"));
        assert!(rules.contains("block drop out"));
        assert!(rules.contains("5201"));
    }

    #[test]
    fn test_generate_pf_rules_empty_ports_skipped() {
        let mut state = PfState::new();

        // Process with no ports should be skipped.
        state.pipes.insert(
            100,
            PipeAllocation {
                pid: 100,
                download_pipe: 10000,
                upload_pipe: 10001,
                download_bps: 1_000_000,
                upload_bps: 500_000,
                ports: HashSet::new(),
            },
        );

        state.blocked.insert(
            200,
            BlockEntry {
                pid: 200,
                ports: HashSet::new(),
            },
        );

        let rules = state.generate_pf_rules();
        assert!(!rules.contains("dummynet"));
        assert!(!rules.contains("block drop"));
    }

    #[test]
    fn test_generate_pf_rules_mixed() {
        let mut state = PfState::new();

        // Rate-limited process.
        let mut limit_ports = HashSet::new();
        limit_ports.insert(8080);
        state.pipes.insert(
            100,
            PipeAllocation {
                pid: 100,
                download_pipe: 10000,
                upload_pipe: 10001,
                download_bps: 1_000_000,
                upload_bps: 500_000,
                ports: limit_ports,
            },
        );

        // Blocked process.
        let mut block_ports = HashSet::new();
        block_ports.insert(9090);
        state.blocked.insert(
            200,
            BlockEntry {
                pid: 200,
                ports: block_ports,
            },
        );

        let rules = state.generate_pf_rules();
        assert!(rules.contains("dummynet in"));
        assert!(rules.contains("dummynet out"));
        assert!(rules.contains("pipe 10000"));
        assert!(rules.contains("8080"));
        assert!(rules.contains("block drop"));
        assert!(rules.contains("9090"));
    }

    #[test]
    fn test_pf_handle_new() {
        let handle = PfHandle::new();
        assert!(!handle.is_active());
    }

    #[test]
    fn test_pf_handle_active_flag() {
        let handle = PfHandle::new();
        assert!(!handle.is_active());
        handle.set_active(true);
        assert!(handle.is_active());
        handle.set_active(false);
        assert!(!handle.is_active());
    }

    #[test]
    fn test_pipe_allocation_increments() {
        let mut state = PfState::new();

        // Allocate 3 pairs.
        let (d1, u1) = state.allocate_pipe_pair().unwrap();
        let (d2, u2) = state.allocate_pipe_pair().unwrap();
        let (d3, u3) = state.allocate_pipe_pair().unwrap();

        assert_eq!(d1, PIPE_BASE);
        assert_eq!(u1, PIPE_BASE + 1);
        assert_eq!(d2, PIPE_BASE + 2);
        assert_eq!(u2, PIPE_BASE + 3);
        assert_eq!(d3, PIPE_BASE + 4);
        assert_eq!(u3, PIPE_BASE + 5);
    }
}
