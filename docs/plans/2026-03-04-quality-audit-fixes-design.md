# Quality Audit Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all P0-P2 issues identified in the project audit: unused dependencies, missing release profile, memory leaks, test gaps, and CI improvements.

**Architecture:** Three-phase approach — Phase 1 cleans up build config and CI (low risk, no behavior change), Phase 2 adds lifecycle management for unbounded data structures (medium risk, behavior change), Phase 3 adds tests for untested hot paths and frontend components.

**Tech Stack:** Rust, Tauri v2, React 19, Vitest 4, @testing-library/react 16

---

## Phase 1: Quick Fixes

### Task 1: Remove Unused Dependencies and Optimize Cargo.toml

**Files:**
- Modify: `src-tauri/Cargo.toml` (lines 11, 21, 25)

**Step 1: Remove `governor` dependency**

In `src-tauri/Cargo.toml`, delete line 25 (`governor = "0.7"`). This crate has zero imports anywhere in the source.

**Step 2: Remove `tokio` dependency**

In `src-tauri/Cargo.toml`, delete line 21 (`tokio = { version = "1", features = ["full"] }`). The project uses `std::thread` exclusively; Tauri provides tokio as a transitive dependency.

**Step 3: Remove `"cdylib"` from crate-type**

In `src-tauri/Cargo.toml`, change line 11 from:
```toml
crate-type = ["staticlib", "cdylib", "rlib"]
```
to:
```toml
crate-type = ["staticlib", "rlib"]
```
`"cdylib"` is for dynamic libraries / mobile; removing it avoids compiling the library a third time.

**Step 4: Verify the project still compiles**

Run: `cd src-tauri && cargo check`
Expected: Compiles with no errors. If removing `tokio` causes an error (Tauri may need a feature that its own dep doesn't enable), add it back with minimal features: `tokio = { version = "1", features = [] }` and re-check.

**Step 5: Add release profile**

Append to the end of `src-tauri/Cargo.toml`:
```toml

[profile.release]
opt-level = "s"
lto = "thin"
strip = "symbols"
codegen-units = 1
```

**Step 6: Verify release check passes**

Run: `cd src-tauri && cargo check --release`
Expected: Compiles cleanly.

**Step 7: Commit**

```bash
git add src-tauri/Cargo.toml
git commit -m "chore: remove unused deps (governor, tokio, cdylib) and add release profile"
```

---

### Task 2: Fix Stale Doc Comment and Production .unwrap()

**Files:**
- Modify: `src-tauri/src/core/rate_limiter.rs` (line 4)
- Modify: `src-tauri/src/services.rs` (line 232)

**Step 1: Fix stale doc comment in rate_limiter.rs**

In `src-tauri/src/core/rate_limiter.rs`, change line 4 from:
```rust
//! Burst allowance is 2x the configured rate. Uses tokio timers for precise delays.
```
to:
```rust
//! Burst allowance is 2× the configured rate.
```

**Step 2: Fix .unwrap() in services.rs**

In `src-tauri/src/services.rs`, change line 232 from:
```rust
        .icon(app.default_window_icon().cloned().unwrap())
```
to:
```rust
        .icon(app.default_window_icon().cloned().expect("default window icon must be configured in tauri.conf.json"))
```

**Step 3: Verify compilation**

Run: `cd src-tauri && cargo check`
Expected: Clean.

**Step 4: Commit**

```bash
git add src-tauri/src/core/rate_limiter.rs src-tauri/src/services.rs
git commit -m "fix: correct stale doc comment and improve panic message for missing tray icon"
```

---

### Task 3: Repository Cleanup

**Files:**
- Delete: `nul` (root directory, 0-byte Windows artifact)
- Modify: `.gitignore` (add `nul` entry)

**Step 1: Delete the nul file**

Run: `rm -f nul`

**Step 2: Add `nul` to .gitignore**

In `.gitignore`, after line 25 (`desktop.ini`), add:
```
nul
```

**Step 3: Narrow bundle targets in tauri.conf.json**

In `src-tauri/tauri.conf.json`, change line 26 from:
```json
    "targets": "all",
```
to:
```json
    "targets": ["nsis", "msi"],
```
This avoids attempting unsupported bundle formats on Windows.

**Step 4: Commit**

```bash
git add .gitignore src-tauri/tauri.conf.json
git commit -m "chore: clean up nul artifact, narrow bundle targets to nsis+msi"
```

---

### Task 4: CI Improvements

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Add Rust caching and cargo audit to check-windows job**

Replace the entire `.github/workflows/ci.yml` content with:

```yaml
name: CI

on:
  push:
    branches: [master]
    tags: ["v*"]
  pull_request:
    branches: [master]

permissions:
  contents: write

jobs:
  # ── Lint & Test (Windows) ──────────────────────────────────────────
  check-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy

      - name: Rust dependency cache
        uses: Swatinem/rust-cache@v2
        with:
          workspaces: src-tauri

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm

      - name: Install frontend dependencies
        run: npm ci

      - name: Rust format check
        working-directory: src-tauri
        run: cargo fmt --all -- --check

      - name: Rust clippy
        working-directory: src-tauri
        run: cargo clippy --all-targets -- -D warnings

      - name: Rust tests (lib)
        working-directory: src-tauri
        run: cargo test --lib

      - name: Install cargo-audit
        run: cargo install cargo-audit --locked

      - name: Rust dependency audit
        working-directory: src-tauri
        run: cargo audit

      - name: TypeScript type check
        run: npx tsc --noEmit

      - name: Frontend tests
        run: npm test

  # ── Build Windows Installer ────────────────────────────────────────
  build-windows:
    needs: [check-windows]
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Rust dependency cache
        uses: Swatinem/rust-cache@v2
        with:
          workspaces: src-tauri

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm

      - name: Install frontend dependencies
        run: npm ci

      - name: Build Tauri app
        run: npm run tauri build

      - name: Upload Windows artifacts
        uses: actions/upload-artifact@v4
        with:
          name: windows-installers
          path: |
            src-tauri/target/release/bundle/nsis/*.exe
            src-tauri/target/release/bundle/msi/*.msi

  # ── Create GitHub Release ──────────────────────────────────────────
  release:
    needs: [build-windows]
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download Windows artifacts
        uses: actions/download-artifact@v4
        with:
          name: windows-installers
          path: artifacts/windows

      - name: List artifacts
        run: find artifacts -type f

      - name: Upload to GitHub Release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          TAG="${GITHUB_REF#refs/tags/}"
          FILES=$(find artifacts -type f \( -name "*.exe" -o -name "*.msi" \))
          # Create release if it doesn't already exist
          if ! gh release view "$TAG" > /dev/null 2>&1; then
            gh release create "$TAG" \
              --title "$TAG" \
              --prerelease \
              --generate-notes \
              $FILES
          else
            # Release exists (e.g. created manually), just upload assets
            gh release upload "$TAG" $FILES --clobber
          fi
```

Changes from the original:
- Added `Swatinem/rust-cache@v2` to both `check-windows` and `build-windows` jobs
- Added `cargo-audit` install + `cargo audit` step
- Added `npx tsc --noEmit` for TypeScript type checking

**Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add Rust caching, cargo audit, and TypeScript type checking"
```

---

## Phase 2: Memory Leak Fixes

### Task 5: Add Dead Process Cleanup to ProcessMapper

**Files:**
- Modify: `src-tauri/src/core/process_mapper.rs` (lines 73-99, 114-134)
- Modify: `src-tauri/src/config.rs` (add constant)
- Test: `src-tauri/src/core/process_mapper.rs` (existing test module)

**Step 1: Add cleanup interval constant to config.rs**

In `src-tauri/src/config.rs`, after line 32 (`pub const PROCESS_SCAN_INTERVAL_MS: u64 = 500;`), add:
```rust

/// Number of scan cycles between dead-process cleanup sweeps.
/// At 500ms intervals, 10 cycles = 5 seconds.
pub const STALE_PID_CLEANUP_INTERVAL: u64 = 10;
```

**Step 2: Write the failing test for process_info cleanup**

In `src-tauri/src/core/process_mapper.rs`, add to the test module (after line 172):
```rust

    #[test]
    fn test_retain_live_pids_removes_dead() {
        let mapper = ProcessMapper::new();
        // Manually insert entries for PIDs 1, 2, 3
        mapper.process_info.insert(1, ProcessInfo {
            name: "alive".into(),
            exe_path: "/alive".into(),
        });
        mapper.process_info.insert(2, ProcessInfo {
            name: "dead".into(),
            exe_path: "/dead".into(),
        });
        mapper.process_info.insert(3, ProcessInfo {
            name: "also_alive".into(),
            exe_path: "/also_alive".into(),
        });

        let mut live = std::collections::HashSet::new();
        live.insert(1u32);
        live.insert(3u32);
        mapper.retain_live_pids(&live);

        assert!(mapper.get_process_info(1).is_some());
        assert!(mapper.get_process_info(2).is_none(), "dead PID should be removed");
        assert!(mapper.get_process_info(3).is_some());
    }

    #[test]
    fn test_retain_live_pids_empty_set_clears_all() {
        let mapper = ProcessMapper::new();
        mapper.process_info.insert(1, ProcessInfo {
            name: "test".into(),
            exe_path: "/test".into(),
        });
        mapper.retain_live_pids(&std::collections::HashSet::new());
        assert!(mapper.get_process_info(1).is_none());
    }
```

**Step 3: Run tests to verify they fail**

Run: `cd src-tauri && cargo test --lib process_mapper::tests`
Expected: FAIL — `retain_live_pids` method does not exist.

**Step 4: Implement `retain_live_pids` method**

In `src-tauri/src/core/process_mapper.rs`, add a new public method after line 68 (`connection_counts` closing brace) and before line 71 (`start_scanning`):
```rust

    /// Remove entries from `process_info` for PIDs that are no longer alive.
    pub fn retain_live_pids(&self, live_pids: &std::collections::HashSet<u32>) {
        self.process_info.retain(|pid, _| live_pids.contains(pid));
    }
```

**Step 5: Run tests to verify they pass**

Run: `cd src-tauri && cargo test --lib process_mapper::tests`
Expected: All PASS.

**Step 6: Wire cleanup into the scanner loop**

In `src-tauri/src/core/process_mapper.rs`, modify `start_scanning` (lines 73-99). Add a counter and call `retain_live_pids` every N cycles.

Replace the spawn closure body (lines 80-96) with:
```rust
            .spawn(move || {
                let mut sys = System::new();
                let interval = std::time::Duration::from_millis(config::PROCESS_SCAN_INTERVAL_MS);
                let step = std::time::Duration::from_millis(50);
                let mut scan_counter: u64 = 0;
                while !shutdown.load(Ordering::Relaxed) {
                    win_net_table::refresh_port_map(&mapper.port_map);
                    mapper.refresh_process_info(&mut sys);

                    scan_counter += 1;
                    if scan_counter % config::STALE_PID_CLEANUP_INTERVAL == 0 {
                        let live_pids: std::collections::HashSet<u32> = sys
                            .processes()
                            .keys()
                            .map(|p| p.as_u32())
                            .collect();
                        mapper.retain_live_pids(&live_pids);
                    }

                    // Interruptible sleep: check shutdown flag every 50ms.
                    let mut elapsed = std::time::Duration::ZERO;
                    while elapsed < interval {
                        if shutdown.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(step);
                        elapsed += step;
                    }
                }
            })
```

**Step 7: Verify compilation**

Run: `cd src-tauri && cargo check`
Expected: Clean.

**Step 8: Commit**

```bash
git add src-tauri/src/core/process_mapper.rs src-tauri/src/config.rs
git commit -m "fix: add dead process cleanup to ProcessMapper (every 5s sweep)"
```

---

### Task 6: Add Stale PID Cleanup to RateLimiterManager

**Files:**
- Modify: `src-tauri/src/core/rate_limiter.rs` (add method after line 193)
- Modify: `src-tauri/src/core/process_mapper.rs` (wire into scanner, expose live_pids)
- Test: `src-tauri/src/core/rate_limiter.rs` (existing test module)

**Step 1: Write the failing test**

In `src-tauri/src/core/rate_limiter.rs`, add to the test module (find the `#[cfg(test)] mod tests` section):
```rust

    #[test]
    fn test_remove_stale_pids_cleans_limits_and_blocks() {
        let mgr = RateLimiterManager::new();
        mgr.set_limit(100, BandwidthLimit { download_bps: 1000, upload_bps: 500 });
        mgr.set_limit(200, BandwidthLimit { download_bps: 2000, upload_bps: 1000 });
        mgr.block_process(300);

        let mut live = std::collections::HashSet::new();
        live.insert(200u32); // only PID 200 is alive
        mgr.remove_stale_pids(&live);

        // PID 100 limit should be gone
        assert!(mgr.get_all_limits().get(&100).is_none());
        // PID 200 limit should remain
        assert!(mgr.get_all_limits().get(&200).is_some());
        // PID 300 block should be gone
        assert!(!mgr.get_blocked_pids().contains(&300));
    }

    #[test]
    fn test_remove_stale_pids_empty_live_set() {
        let mgr = RateLimiterManager::new();
        mgr.set_limit(1, BandwidthLimit { download_bps: 100, upload_bps: 50 });
        mgr.block_process(2);

        mgr.remove_stale_pids(&std::collections::HashSet::new());

        assert!(mgr.get_all_limits().is_empty());
        assert!(mgr.get_blocked_pids().is_empty());
    }
```

**Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test --lib rate_limiter::tests::test_remove_stale`
Expected: FAIL — `remove_stale_pids` method does not exist.

**Step 3: Implement `remove_stale_pids`**

In `src-tauri/src/core/rate_limiter.rs`, add after line 193 (after `clear_all` method, before the closing `}` of `impl RateLimiterManager`):
```rust

    /// Remove limits and blocks for PIDs that are no longer alive.
    /// Prevents stale entries from accumulating and fixes PID-reuse inheritance bugs.
    pub fn remove_stale_pids(&self, live_pids: &std::collections::HashSet<u32>) {
        self.limiters.lock().retain(|pid, _| live_pids.contains(pid));
        self.limits_config.lock().retain(|pid, _| live_pids.contains(pid));
        self.blocked_pids.lock().retain(|pid| live_pids.contains(pid));
    }
```

**Step 4: Run tests to verify they pass**

Run: `cd src-tauri && cargo test --lib rate_limiter::tests`
Expected: All PASS.

**Step 5: Wire into scanner loop**

The scanner already computes `live_pids` in Task 5. To pass it to the rate limiter, modify `ProcessMapper::start_scanning` to also accept an `Arc<RateLimiterManager>` parameter.

In `src-tauri/src/core/process_mapper.rs`, change the `start_scanning` signature (line 73-75) from:
```rust
    pub fn start_scanning(
        self: &Arc<Self>,
        shutdown: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<()> {
```
to:
```rust
    pub fn start_scanning(
        self: &Arc<Self>,
        rate_limiter: Arc<crate::core::rate_limiter::RateLimiterManager>,
        shutdown: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<()> {
```

And in the closure body, after `mapper.retain_live_pids(&live_pids);`, add:
```rust
                        rate_limiter.remove_stale_pids(&live_pids);
```

**Step 6: Update the call site in services.rs**

In `src-tauri/src/services.rs`, find line 56 where `start_scanning` is called:
```rust
            process_mapper.start_scanning(Arc::clone(&shutdown)),
```
Change to:
```rust
            process_mapper.start_scanning(Arc::clone(rate_limiter), Arc::clone(&shutdown)),
```

**Step 7: Verify compilation and tests**

Run: `cd src-tauri && cargo check && cargo test --lib`
Expected: All pass.

**Step 8: Commit**

```bash
git add src-tauri/src/core/rate_limiter.rs src-tauri/src/core/process_mapper.rs src-tauri/src/services.rs
git commit -m "fix: add stale PID cleanup to RateLimiterManager, wire into scanner loop"
```

---

### Task 7: Fix notified_pids Leak and Add DB Transaction for Batch Inserts

**Files:**
- Modify: `src-tauri/src/services.rs` (line 335, in `update_tray_and_notify`)
- Modify: `src-tauri/src/db/history.rs` (lines 10-29, `insert_traffic_batch`)

**Step 1: Fix notified_pids leak**

In `src-tauri/src/services.rs`, in the `update_tray_and_notify` function, after line 335 (closing `}` of `if threshold_bps > 0` block), add:
```rust

    // Clean up notified_pids for processes no longer in the snapshot.
    let snapshot_pids: HashSet<u32> = snapshot.iter().map(|p| p.pid).collect();
    notified_pids.retain(|pid| snapshot_pids.contains(pid));
```

**Step 2: Wrap batch insert in a transaction**

In `src-tauri/src/db/history.rs`, replace the `insert_traffic_batch` method (lines 10-29) with:
```rust
    pub fn insert_traffic_batch(&self, records: &[TrafficRecord]) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch("BEGIN")?;
        let result = (|| {
            let mut stmt = conn.prepare_cached(
                "INSERT INTO traffic_history (timestamp, pid, process_name, exe_path, bytes_sent, bytes_recv, upload_speed, download_speed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for r in records {
                stmt.execute(params![
                    r.timestamp,
                    r.pid,
                    r.process_name,
                    r.exe_path,
                    r.bytes_sent,
                    r.bytes_recv,
                    r.upload_speed,
                    r.download_speed,
                ])?;
            }
            Ok(())
        })();
        match &result {
            Ok(()) => conn.execute_batch("COMMIT")?,
            Err(_) => { let _ = conn.execute_batch("ROLLBACK"); }
        }
        result
    }
```

**Step 3: Run existing DB tests to ensure no regression**

Run: `cd src-tauri && cargo test --lib db::history::tests`
Expected: All PASS.

**Step 4: Verify full compilation**

Run: `cd src-tauri && cargo check`
Expected: Clean.

**Step 5: Commit**

```bash
git add src-tauri/src/services.rs src-tauri/src/db/history.rs
git commit -m "fix: clean up stale notified_pids, wrap batch inserts in transaction"
```

---

## Phase 3: Test Coverage

### Task 8: Add Tests for Capture Hot Path Functions

**Files:**
- Modify: `src-tauri/src/capture/windivert_backend.rs` (change `fn` to `pub(crate) fn` on lines 157, 182)
- Create: `src-tauri/src/capture/windivert_backend_tests.rs` (or add `#[cfg(test)]` module in windivert_backend.rs)

**Step 1: Make the two functions testable**

In `src-tauri/src/capture/windivert_backend.rs`:

Change line 157 from:
```rust
fn process_sniff_packet(
```
to:
```rust
pub(crate) fn process_sniff_packet(
```

Change line 182 from:
```rust
fn should_pass_packet(
```
to:
```rust
pub(crate) fn should_pass_packet(
```

**Step 2: Write tests for `process_sniff_packet`**

Add a `#[cfg(test)]` module at the end of `src-tauri/src/capture/windivert_backend.rs` (after line 199):

```rust

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::mod_test_helpers::build_ipv4_packet;

    #[test]
    fn test_sniff_outbound_records_upload() {
        let mapper = ProcessMapper::new();
        let tracker = TrafficTracker::new();
        // Manually insert a port→PID mapping
        mapper.port_map.insert((crate::core::process_mapper::Protocol::Tcp, 12345), 42);

        let pkt = build_ipv4_packet(6, 12345, 443); // TCP, src=12345
        process_sniff_packet(&mapper, &tracker, &pkt, true); // outbound

        let snap = tracker.snapshot(&mapper);
        let proc = snap.iter().find(|s| s.pid == 42);
        assert!(proc.is_some(), "PID 42 should appear in snapshot");
        assert!(proc.unwrap().bytes_sent > 0, "outbound bytes should be recorded as sent");
        assert_eq!(proc.unwrap().bytes_recv, 0);
    }

    #[test]
    fn test_sniff_inbound_records_download() {
        let mapper = ProcessMapper::new();
        let tracker = TrafficTracker::new();
        mapper.port_map.insert((crate::core::process_mapper::Protocol::Tcp, 443), 42);

        let pkt = build_ipv4_packet(6, 12345, 443); // TCP, dst=443
        process_sniff_packet(&mapper, &tracker, &pkt, false); // inbound

        let snap = tracker.snapshot(&mapper);
        let proc = snap.iter().find(|s| s.pid == 42);
        assert!(proc.is_some(), "PID 42 should appear in snapshot");
        assert_eq!(proc.unwrap().bytes_sent, 0);
        assert!(proc.unwrap().bytes_recv > 0, "inbound bytes should be recorded as recv");
    }

    #[test]
    fn test_sniff_malformed_packet_no_panic() {
        let mapper = ProcessMapper::new();
        let tracker = TrafficTracker::new();
        process_sniff_packet(&mapper, &tracker, &[0xFF, 0x00], true);
        // Should not panic; snapshot should be empty
        assert!(tracker.snapshot(&mapper).is_empty());
    }

    #[test]
    fn test_sniff_unknown_pid_no_record() {
        let mapper = ProcessMapper::new();
        let tracker = TrafficTracker::new();
        // No port mapping inserted — PID lookup will return None
        let pkt = build_ipv4_packet(6, 9999, 80);
        process_sniff_packet(&mapper, &tracker, &pkt, true);
        assert!(tracker.snapshot(&mapper).is_empty());
    }

    #[test]
    fn test_sniff_empty_packet_no_panic() {
        let mapper = ProcessMapper::new();
        let tracker = TrafficTracker::new();
        process_sniff_packet(&mapper, &tracker, &[], true);
        assert!(tracker.snapshot(&mapper).is_empty());
    }

    #[test]
    fn test_should_pass_unparseable_returns_true() {
        let mapper = ProcessMapper::new();
        let limiter = RateLimiterManager::new();
        // Fail-open: unparseable packet should pass
        assert!(should_pass_packet(&mapper, &limiter, &[0xFF], true));
    }

    #[test]
    fn test_should_pass_unknown_pid_returns_true() {
        let mapper = ProcessMapper::new();
        let limiter = RateLimiterManager::new();
        let pkt = build_ipv4_packet(6, 9999, 80);
        // No port mapping → unknown PID → should pass (fail-open)
        assert!(should_pass_packet(&mapper, &limiter, &pkt, true));
    }

    #[test]
    fn test_should_pass_no_limit_returns_true() {
        let mapper = ProcessMapper::new();
        let limiter = RateLimiterManager::new();
        mapper.port_map.insert((crate::core::process_mapper::Protocol::Tcp, 5000), 42);
        let pkt = build_ipv4_packet(6, 5000, 80);
        // PID known but no limit set → should pass
        assert!(should_pass_packet(&mapper, &limiter, &pkt, true));
    }

    #[test]
    fn test_should_pass_blocked_pid_returns_false() {
        let mapper = ProcessMapper::new();
        let limiter = RateLimiterManager::new();
        mapper.port_map.insert((crate::core::process_mapper::Protocol::Tcp, 5000), 42);
        limiter.block_process(42);
        let pkt = build_ipv4_packet(6, 5000, 80);
        // PID is blocked → should NOT pass
        assert!(!should_pass_packet(&mapper, &limiter, &pkt, true));
    }

    #[test]
    fn test_should_pass_within_rate_budget() {
        let mapper = ProcessMapper::new();
        let limiter = RateLimiterManager::new();
        mapper.port_map.insert((crate::core::process_mapper::Protocol::Tcp, 5000), 42);
        limiter.set_limit(42, crate::core::rate_limiter::BandwidthLimit {
            download_bps: 1_000_000,
            upload_bps: 1_000_000,
        });
        let pkt = build_ipv4_packet(6, 5000, 80); // 24-byte packet
        // Small packet within a 1MB/s budget → should pass
        assert!(should_pass_packet(&mapper, &limiter, &pkt, true));
    }
}
```

**Step 3: Make test helpers accessible across capture submodules**

The `build_ipv4_packet` helper is currently in `capture/mod.rs` tests. To share it, add a `pub(crate)` helper module.

In `src-tauri/src/capture/mod.rs`, add before the `#[cfg(test)]` block (before line 198):
```rust

/// Test helpers shared between capture submodules.
#[cfg(test)]
pub(crate) mod mod_test_helpers {
    /// Build a minimal valid IPv4 packet with the given protocol byte and transport ports.
    pub fn build_ipv4_packet(protocol: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let total_length: u16 = 24;
        let mut pkt = vec![0u8; total_length as usize];
        pkt[0] = 0x45;
        pkt[2] = (total_length >> 8) as u8;
        pkt[3] = (total_length & 0xFF) as u8;
        pkt[9] = protocol;
        pkt[20] = (src_port >> 8) as u8;
        pkt[21] = (src_port & 0xFF) as u8;
        pkt[22] = (dst_port >> 8) as u8;
        pkt[23] = (dst_port & 0xFF) as u8;
        pkt
    }
}
```

Also update the existing tests in `capture/mod.rs` to use this shared helper instead of their local copy. In the existing `#[cfg(test)] mod tests` block, replace the local `build_ipv4_packet` function with:
```rust
    use super::mod_test_helpers::build_ipv4_packet;
```
Keep `build_ipv6_packet` local since only `mod.rs` tests use it.

**Step 4: Make `port_map` accessible for tests**

In `src-tauri/src/core/process_mapper.rs`, change line 35 from:
```rust
    port_map: DashMap<(Protocol, u16), u32>,
```
to:
```rust
    pub(crate) port_map: DashMap<(Protocol, u16), u32>,
```

**Step 5: Run tests**

Run: `cd src-tauri && cargo test --lib capture`
Expected: All PASS — both existing 8 tests and 10 new tests.

**Step 6: Commit**

```bash
git add src-tauri/src/capture/ src-tauri/src/core/process_mapper.rs
git commit -m "test: add 10 unit tests for capture hot path (process_sniff_packet, should_pass_packet)"
```

---

### Task 9: Add Tauri API Mock Infrastructure for Frontend Tests

**Files:**
- Create: `src/__mocks__/@tauri-apps/api/core.ts`
- Create: `src/__mocks__/@tauri-apps/api/event.ts`
- Modify: `vitest.config.ts` (may need alias config)

**Step 1: Create the mock directory structure**

Run: `mkdir -p src/__mocks__/@tauri-apps/api`

**Step 2: Create the core mock**

Create `src/__mocks__/@tauri-apps/api/core.ts`:
```typescript
import { vi } from "vitest";

export const invoke = vi.fn().mockResolvedValue(undefined);
```

**Step 3: Create the event mock**

Create `src/__mocks__/@tauri-apps/api/event.ts`:
```typescript
import { vi } from "vitest";

const noop = () => {};
export const listen = vi.fn().mockResolvedValue(noop);
export const emit = vi.fn().mockResolvedValue(undefined);
```

**Step 4: Verify mock resolution works**

Run: `npm test`
Expected: Existing 36 tests still pass (they don't use Tauri APIs).

**Step 5: Commit**

```bash
git add src/__mocks__/
git commit -m "test: add Tauri API mock infrastructure for frontend component/hook tests"
```

---

### Task 10: Add Frontend UI Component Tests

**Files:**
- Create: `src/components/ui/Toggle.test.tsx`
- Create: `src/components/ui/Badge.test.tsx`

**Step 1: Create Toggle tests**

Create `src/components/ui/Toggle.test.tsx`:
```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { Toggle } from "./Toggle";

describe("Toggle", () => {
  it("renders in off state", () => {
    render(<Toggle on={false} onToggle={() => {}} />);
    const btn = screen.getByRole("button");
    expect(btn.className).not.toContain("is-on");
  });

  it("renders in on state", () => {
    render(<Toggle on={true} onToggle={() => {}} />);
    const btn = screen.getByRole("button");
    expect(btn.className).toContain("is-on");
  });

  it("calls onToggle when clicked", () => {
    const handler = vi.fn();
    render(<Toggle on={false} onToggle={handler} />);
    fireEvent.click(screen.getByRole("button"));
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("applies custom color when on", () => {
    render(<Toggle on={true} onToggle={() => {}} color="#ff0000" />);
    const btn = screen.getByRole("button");
    expect(btn.style.backgroundColor).toBe("rgb(255, 0, 0)");
  });
});
```

**Step 2: Create Badge tests**

Create `src/components/ui/Badge.test.tsx`:
```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { Badge } from "./Badge";

describe("Badge", () => {
  it("renders children text", () => {
    render(<Badge color="neon">Active</Badge>);
    expect(screen.getByText("Active")).toBeDefined();
  });

  it("applies the correct color class for each variant", () => {
    const { rerender } = render(<Badge color="danger">X</Badge>);
    expect(screen.getByText("X").className).toContain("text-danger");

    rerender(<Badge color="caution">X</Badge>);
    expect(screen.getByText("X").className).toContain("text-caution");

    rerender(<Badge color="neon">X</Badge>);
    expect(screen.getByText("X").className).toContain("text-neon");

    rerender(<Badge color="iris">X</Badge>);
    expect(screen.getByText("X").className).toContain("text-iris");
  });
});
```

**Step 3: Run frontend tests**

Run: `npm test`
Expected: 36 existing + 6 new = 42 tests pass.

**Step 4: Commit**

```bash
git add src/components/ui/Toggle.test.tsx src/components/ui/Badge.test.tsx
git commit -m "test: add unit tests for Toggle and Badge UI components"
```

---

### Task 11: Add Hook Tests (useSettings)

**Files:**
- Create: `src/hooks/useSettings.test.ts`

**Step 1: Create useSettings tests**

Create `src/hooks/useSettings.test.ts`:
```typescript
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

// Mock Tauri APIs before importing the hook
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
}));

import { useSettings } from "./useSettings";
import { invoke } from "@tauri-apps/api/core";

const mockedInvoke = vi.mocked(invoke);

describe("useSettings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedInvoke.mockResolvedValue(undefined as any);
  });

  it("initializes with default values", () => {
    const { result } = renderHook(() => useSettings());
    expect(result.current.showSettings).toBe(false);
    expect(result.current.notifThreshold).toBe(0);
    expect(result.current.autostart).toBe(false);
    expect(result.current.interceptActive).toBe(false);
  });

  it("fetches initial settings on mount", async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "get_notification_threshold") return 1024;
      if (cmd === "get_autostart") return true;
      if (cmd === "is_intercept_active") return false;
      return undefined;
    });

    const { result } = renderHook(() => useSettings());

    await waitFor(() => {
      expect(result.current.notifThreshold).toBe(1024);
    });
    expect(result.current.autostart).toBe(true);
    expect(result.current.interceptActive).toBe(false);
  });

  it("invokes all three setting commands on mount", () => {
    renderHook(() => useSettings());
    expect(mockedInvoke).toHaveBeenCalledWith("get_notification_threshold");
    expect(mockedInvoke).toHaveBeenCalledWith("get_autostart");
    expect(mockedInvoke).toHaveBeenCalledWith("is_intercept_active");
  });
});
```

**Step 2: Run frontend tests**

Run: `npm test`
Expected: All pass including 3 new hook tests.

**Step 3: Commit**

```bash
git add src/hooks/useSettings.test.ts
git commit -m "test: add unit tests for useSettings hook with Tauri API mocks"
```

---

### Task 12: Add apply_persistent_rules Tests

**Files:**
- Modify: `src-tauri/src/services.rs` (add to existing `#[cfg(test)]` module)

**Step 1: Add tests for `apply_persistent_rules`**

In `src-tauri/src/services.rs`, add to the existing test module (after line 446):

```rust

    #[test]
    fn test_apply_persistent_rules_matching_exe() {
        let tracker = TrafficTracker::new();
        let mapper = ProcessMapper::new();
        let limiter = RateLimiterManager::new();
        let rules = Mutex::new(vec![db::SavedRule {
            profile_name: "test".into(),
            exe_path: "/usr/bin/app".into(),
            download_bps: 5000,
            upload_bps: 3000,
            blocked: false,
        }]);

        // Simulate a process with matching exe_path in the tracker
        mapper.process_info.insert(
            10,
            crate::core::process_mapper::ProcessInfo {
                name: "app".into(),
                exe_path: "/usr/bin/app".into(),
            },
        );
        tracker.record_bytes(10, 100, 0);

        apply_persistent_rules(&tracker, &mapper, &limiter, &rules);

        let limits = limiter.get_all_limits();
        assert!(limits.contains_key(&10), "PID 10 should have a limit applied");
        assert_eq!(limits[&10].download_bps, 5000);
        assert_eq!(limits[&10].upload_bps, 3000);
    }

    #[test]
    fn test_apply_persistent_rules_no_match() {
        let tracker = TrafficTracker::new();
        let mapper = ProcessMapper::new();
        let limiter = RateLimiterManager::new();
        let rules = Mutex::new(vec![db::SavedRule {
            profile_name: "test".into(),
            exe_path: "/other/app".into(),
            download_bps: 1000,
            upload_bps: 500,
            blocked: false,
        }]);

        mapper.process_info.insert(
            10,
            crate::core::process_mapper::ProcessInfo {
                name: "app".into(),
                exe_path: "/usr/bin/app".into(),
            },
        );
        tracker.record_bytes(10, 100, 0);

        apply_persistent_rules(&tracker, &mapper, &limiter, &rules);

        assert!(limiter.get_all_limits().is_empty(), "no match = no limits applied");
    }

    #[test]
    fn test_apply_persistent_rules_block() {
        let tracker = TrafficTracker::new();
        let mapper = ProcessMapper::new();
        let limiter = RateLimiterManager::new();
        let rules = Mutex::new(vec![db::SavedRule {
            profile_name: "test".into(),
            exe_path: "/usr/bin/blocked_app".into(),
            download_bps: 0,
            upload_bps: 0,
            blocked: true,
        }]);

        mapper.process_info.insert(
            20,
            crate::core::process_mapper::ProcessInfo {
                name: "blocked_app".into(),
                exe_path: "/usr/bin/blocked_app".into(),
            },
        );
        tracker.record_bytes(20, 50, 0);

        apply_persistent_rules(&tracker, &mapper, &limiter, &rules);

        assert!(limiter.get_blocked_pids().contains(&20), "PID 20 should be blocked");
    }
```

**Step 2: Make `process_info` field accessible for tests**

The `process_info` field in `ProcessMapper` is currently private. We already made `port_map` `pub(crate)` in Task 8. Do the same for `process_info`.

In `src-tauri/src/core/process_mapper.rs`, change line 37 from:
```rust
    process_info: DashMap<u32, ProcessInfo>,
```
to:
```rust
    pub(crate) process_info: DashMap<u32, ProcessInfo>,
```

**Step 3: Run tests**

Run: `cd src-tauri && cargo test --lib services::tests`
Expected: 3 existing + 3 new = 6 tests pass.

**Step 4: Run full test suite**

Run: `cd src-tauri && cargo test --lib`
Expected: All Rust tests pass.

Run: `npm test`
Expected: All frontend tests pass.

**Step 5: Commit**

```bash
git add src-tauri/src/services.rs src-tauri/src/core/process_mapper.rs
git commit -m "test: add apply_persistent_rules tests with mock AppState"
```

---

### Task 13: Final Verification

**Step 1: Run complete Rust test suite**

Run: `cd src-tauri && cargo test --lib`
Expected: All tests pass (previous ~91 + ~15 new ≈ 106 tests).

**Step 2: Run clippy**

Run: `cd src-tauri && cargo clippy --all-targets -- -D warnings`
Expected: Zero warnings.

**Step 3: Run format check**

Run: `cd src-tauri && cargo fmt --all -- --check`
Expected: No formatting issues.

**Step 4: Run frontend tests**

Run: `npm test`
Expected: All tests pass (~36 + ~9 new ≈ 45 tests).

**Step 5: Full cargo check**

Run: `cd src-tauri && cargo check`
Expected: Clean compilation.

**Step 6: Final commit if any formatting fixes needed**

If `cargo fmt` or clippy required changes:
```bash
git add -A
git commit -m "style: fix formatting from automated checks"
```
