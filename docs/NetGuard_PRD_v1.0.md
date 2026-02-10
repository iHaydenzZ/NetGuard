# NetGuard — Product Requirements Document v1.0

> **Cross-Platform Network Traffic Monitor & Bandwidth Controller**
> Version 1.0 · February 2026 · For Personal Use

---

## 1. Product Overview

### 1.1 Purpose

NetGuard is a lightweight, cross-platform desktop application for monitoring per-process network traffic and controlling bandwidth allocation. It targets personal use on Windows 11 and macOS, providing real-time visibility into which applications consume network resources and enabling fine-grained upload/download speed limiting per process.

### 1.2 Problem Statement

Operating systems provide limited built-in visibility into per-application network usage. Users often experience degraded network performance due to background applications (cloud sync, updates, streaming) consuming disproportionate bandwidth. Existing solutions like NetLimiter are Windows-only, commercial, and overly complex for personal use cases.

### 1.3 Target User

Power users and developers who want to understand and control how their applications use network bandwidth on their personal machines. The primary user is a single individual running the application on one Windows 11 or macOS device at a time.

### 1.4 Design Principles

- **Minimal footprint:** CPU overhead < 2% under normal conditions; memory < 30MB
- **Non-destructive default:** Monitor-only by default; throttling requires explicit user action
- **Fail-open:** If the application crashes, all traffic flows normally with no network disruption
- **Cross-platform parity:** Core features behave identically on Windows and macOS despite different underlying mechanisms
- **Zero runtime dependency:** Single binary, no Python/Node/JRE required on the target machine

---

## 2. Technical Architecture

### 2.1 High-Level Architecture

The application consists of three layers: a platform-specific packet interception backend, a cross-platform core logic layer, and a Tauri-based desktop GUI frontend. Rust is the primary language for performance, memory safety, and single-binary distribution.

| Layer | Component | Technology |
|---|---|---|
| Packet Interception | Windows Backend | WinDivert 2.x via `windivert` crate |
| Packet Interception | macOS Backend | pf (Packet Filter) + dnctl via `nix` crate / `std::process::Command` |
| Core Logic | Traffic Accounting | Rust async runtime (`tokio`) + `DashMap` for lock-free concurrent maps |
| Core Logic | Rate Limiter | Token Bucket algorithm (`governor` crate or custom impl) per process |
| Core Logic | Process Mapper | `sysinfo` crate (cross-platform port-to-PID mapping) |
| Frontend | Desktop GUI | Tauri v2 (Rust backend + HTML/TypeScript/React frontend) |
| Frontend | System Tray | Tauri system tray API |
| Persistence | Config & Rules | SQLite via `rusqlite` + JSON config via `serde` |
| Charts | Real-time Graphs | Recharts / Chart.js in Tauri webview |
| Packaging | Windows | Tauri bundler → NSIS installer (.exe) with UAC elevation manifest |
| Packaging | macOS | Tauri bundler → .dmg with native .app bundle |

### 2.2 Platform-Specific Implementation

#### 2.2.1 Windows (WinDivert)

WinDivert provides user-space packet capture and re-injection on Windows. It ships with a signed kernel driver, eliminating the need for custom driver development. The `windivert` Rust crate provides safe, zero-cost bindings to the WinDivert C API. The application captures packets matching a BPF-like filter, associates them with processes via port-to-PID mapping, applies rate-limiting logic, and re-injects packets after the appropriate delay.

**Key dependency:** WinDivert v2.x (MIT licensed, pre-signed driver). Requires administrator privileges at runtime. The `windivert` crate wraps the C API with safe Rust abstractions, including async recv/send via `tokio`.

#### 2.2.2 macOS (pf + dnctl)

macOS uses the built-in pf (Packet Filter) firewall with dummynet (dnctl) pipes for bandwidth shaping. The application programmatically creates dummynet pipes with specified bandwidth limits and adds pf rules to route traffic from target processes through these pipes. Process-to-connection mapping uses the `libproc` API via FFI bindings or the `sysinfo` crate.

**Key dependency:** pf and dnctl are built into macOS. Requires root privileges. On macOS 15+, Network Extension API may be needed for future-proofing. Pipe configuration is done via `std::process::Command` calling `dnctl` and `pfctl`.

### 2.3 Core Algorithm: Token Bucket Rate Limiter

Each rate-limited process gets its own Token Bucket instance. The bucket fills at the configured rate (bytes/sec). When a packet arrives, if sufficient tokens exist, the packet passes immediately. Otherwise, the packet is queued and released when enough tokens accumulate. A burst allowance of 2x the rate is permitted to avoid excessive micro-buffering.

**Windows implementation:** Token bucket operates in user-space using `tokio::time::sleep` for precise delays. Packets are held in a per-process `tokio::sync::mpsc` channel and re-injected via WinDivert after the calculated delay. The `governor` crate may be used for a battle-tested rate limiter, or a custom implementation can be built for tighter control over burst behavior.

**macOS implementation:** Token bucket logic is delegated to the kernel via dummynet pipes (bandwidth parameter). The Rust application only needs to configure and update pipe parameters via subprocess calls to `dnctl`.

### 2.4 Concurrency Model

```
Main Thread (Tauri event loop / UI)
  │
  ├── Packet Capture Task (tokio::spawn)
  │     └── WinDivert recv loop → classify → route to per-process channel
  │
  ├── Per-Process Throttle Tasks (tokio::spawn, one per limited process)
  │     └── mpsc::Receiver → token bucket wait → WinDivert send
  │
  ├── Stats Aggregator Task (1-second tick)
  │     └── DashMap<PID, TrafficCounters> → compute speeds → emit to frontend
  │
  └── Process Scanner Task (500ms tick)
        └── sysinfo refresh → update port-PID map in DashMap
```

All packet-path operations are lock-free or use fine-grained per-key locks via `DashMap`. The `tokio` runtime handles async scheduling with work-stealing across CPU cores, ensuring that the packet capture loop never blocks on UI or database operations.

---

## 3. Feature Requirements

### 3.1 F1 — Real-Time Process Network Monitor

**Priority:** P0 (Must Have)

Display a live-updating table of all processes with active network connections. Each row shows the process name, PID, icon, current upload speed, current download speed, cumulative bytes sent, cumulative bytes received, and connection count. The table refreshes at 1-second intervals and supports sorting by any column.

| AC ID | Acceptance Criteria | Verification Method |
|---|---|---|
| AC-1.1 | Table displays all processes with active TCP/UDP connections within 3 seconds of app launch | Manual: Launch app, verify process list matches `netstat` output |
| AC-1.2 | Upload/download speed values update every 1 second with ±10% accuracy compared to Wireshark baseline | Automated: Run iperf3 at known rate, assert displayed speed within tolerance |
| AC-1.3 | Cumulative byte counters are accurate to within 1% over a 5-minute monitoring window | Automated: Transfer known file, compare counter to file size |
| AC-1.4 | Table can be sorted by any column (ascending/descending) without disrupting the data stream | Manual: Click column headers during active transfers |
| AC-1.5 | New processes with network activity appear within 2 seconds; terminated processes are removed within 5 seconds | Manual: Start/stop curl, observe table updates |
| AC-1.6 | Process icon and friendly name are resolved correctly for >95% of standard applications | Manual: Verify icons for 20 common apps (browsers, IDEs, etc.) |

### 3.2 F2 — Per-Process Bandwidth Limiting

**Priority:** P0 (Must Have)

Users can set independent upload and download speed limits for any process. Limits are specified in KB/s or MB/s. The rate limiter enforces the configured ceiling using a token bucket algorithm. Multiple processes can be limited simultaneously with independent configurations.

| AC ID | Acceptance Criteria | Verification Method |
|---|---|---|
| AC-2.1 | Setting a 500 KB/s download limit on a process results in actual throughput between 450–550 KB/s | Automated: iperf3 through limited process, measure throughput |
| AC-2.2 | Limits take effect within 2 seconds of being applied | Manual: Apply limit during active download, observe speed graph change |
| AC-2.3 | Removing a limit restores full-speed traffic within 1 second | Manual: Remove limit, observe immediate speed recovery |
| AC-2.4 | 5 or more processes can be simultaneously limited without cross-interference | Automated: Run 5 parallel iperf3 sessions with different limits |
| AC-2.5 | Rate limiting works correctly for both TCP and UDP traffic | Automated: Test with iperf3 in TCP and UDP modes |
| AC-2.6 | Application does not crash or leak memory when limits are rapidly toggled (100 on/off cycles) | Automated: Script rapid toggle, monitor memory and stability |

### 3.3 F3 — Per-Process Connection Blocking (Firewall)

**Priority:** P1 (Should Have)

Users can block all outbound or inbound network access for a specific process. This acts as a simple per-application firewall. Blocked packets are silently dropped. A toggle switch in the UI controls the block state.

| AC ID | Acceptance Criteria | Verification Method |
|---|---|---|
| AC-3.1 | Blocking a process prevents all new outbound TCP connections (connection timeout) | Automated: Block curl, attempt HTTP request, verify failure |
| AC-3.2 | Blocking does not affect existing established connections of OTHER processes | Manual: Block process A while process B has active connections |
| AC-3.3 | Unblocking a process restores network access within 1 second | Manual: Unblock, retry connection immediately |
| AC-3.4 | DNS queries from a blocked process are also blocked | Automated: Block process, attempt DNS resolution, verify failure |

### 3.4 F4 — Traffic History & Statistics

**Priority:** P1 (Should Have)

The application records per-process traffic data to a local SQLite database and provides historical charts. Users can view traffic trends over the last hour, day, week, or month. A summary dashboard shows top consumers by total bandwidth usage.

| AC ID | Acceptance Criteria | Verification Method |
|---|---|---|
| AC-4.1 | Historical data persists across application restarts | Manual: Record traffic, restart app, verify history is intact |
| AC-4.2 | Time-series chart displays per-process bandwidth with 5-second granularity for the last hour | Manual: Generate steady traffic for 10 min, verify chart accuracy |
| AC-4.3 | Top consumers summary correctly ranks processes by total bytes over the selected time window | Manual: Compare ranking against known transfer volumes |
| AC-4.4 | Database size remains under 500 MB after 30 days of continuous monitoring | Automated: Simulate 30 days of data, check DB file size |
| AC-4.5 | Old data (>90 days) is automatically pruned without user intervention | Automated: Insert old records, trigger pruning, verify deletion |

### 3.5 F5 — Rule Profiles & Presets

**Priority:** P2 (Nice to Have)

Users can save sets of bandwidth rules as named profiles (e.g., "Gaming Mode", "Video Call Mode", "Background Only"). Profiles can be activated manually from the UI or system tray. Switching profiles applies all associated rules atomically.

| AC ID | Acceptance Criteria | Verification Method |
|---|---|---|
| AC-5.1 | A profile with 10+ rules can be saved and loaded without data loss | Manual: Create complex profile, reload, verify all rules intact |
| AC-5.2 | Switching between profiles applies all rules within 3 seconds | Manual: Switch profiles during active traffic, time the transition |
| AC-5.3 | Profiles persist across application restarts | Manual: Save profile, restart app, verify profile exists |

### 3.6 F6 — System Tray & Notifications

**Priority:** P1 (Should Have)

The application runs in the system tray by default after initial setup. A tray icon displays a mini traffic indicator. Right-clicking the tray icon provides quick access to current top bandwidth consumers, profile switching, and application toggle. Desktop notifications alert users when a process exceeds a configurable bandwidth threshold.

| AC ID | Acceptance Criteria | Verification Method |
|---|---|---|
| AC-6.1 | Closing the main window minimizes to tray rather than quitting | Manual: Close window, verify tray icon active and monitoring continues |
| AC-6.2 | Tray tooltip shows aggregate upload/download speed, updating every 2 seconds | Manual: Hover tray icon during active traffic |
| AC-6.3 | Right-click menu shows top 5 bandwidth consumers with current speeds | Manual: Right-click tray during active traffic |
| AC-6.4 | Bandwidth threshold notification fires within 5 seconds of the threshold being exceeded | Automated: Set low threshold, generate traffic, time notification |

### 3.7 F7 — Auto-Start & Persistent Rules

**Priority:** P2 (Nice to Have)

The application can be configured to launch at system startup with elevated privileges. Previously configured bandwidth rules are automatically re-applied when the target process is detected. Rules target processes by executable path for reliable matching across sessions.

| AC ID | Acceptance Criteria | Verification Method |
|---|---|---|
| AC-7.1 | Application starts automatically on login when auto-start is enabled | Manual: Enable, reboot, verify app is running |
| AC-7.2 | Persistent rules are applied within 5 seconds of the target process launching | Manual: Set rule for Chrome, restart Chrome, verify limit applied |
| AC-7.3 | Rules match by executable path, not PID (handles process restarts correctly) | Manual: Set rule, kill and restart target process, verify rule re-applies |

---

## 4. Non-Functional Requirements

| Category | Requirement | Acceptance Criteria |
|---|---|---|
| Performance | CPU usage < 2% during monitoring (no throttling active) | AC-NF1: 10-minute average CPU measured by OS task manager < 2% |
| Performance | CPU usage < 5% with 5 processes being actively throttled | AC-NF2: Stress test with 5 iperf3 sessions, CPU < 5% |
| Performance | Added network latency < 0.5ms when no throttling is active (SNIFF mode) | AC-NF3: Ping test shows < 0.5ms added latency vs baseline |
| Memory | RSS memory < 30 MB during normal operation | AC-NF4: Monitor RSS over 1 hour of typical usage |
| Memory | No memory leak: RSS growth < 5 MB over 24 hours of continuous use | AC-NF5: 24-hour soak test, measure start/end RSS |
| Reliability | Application crash does not disrupt network traffic (fail-open) | AC-NF6: Kill process during active throttling, verify traffic resumes |
| Reliability | Graceful handling of rapid process creation/destruction (100 processes/sec) | AC-NF7: Fork bomb test, verify no crash or deadlock |
| Security | No network traffic leaves the machine; all processing is local | AC-NF8: Packet capture shows zero outbound traffic from NetGuard |
| Compatibility | Windows 11 (22H2+) support | AC-NF9: Full test pass on Windows 11 22H2 |
| Compatibility | macOS 13 Ventura+ support (Intel & Apple Silicon) | AC-NF10: Full test pass on macOS 13+ on both architectures |
| Binary Size | Installer < 15 MB on both platforms | AC-NF11: Verify final bundled installer size |
| Startup | Cold start to fully operational monitoring < 3 seconds | AC-NF12: Timed measurement from launch to first data display |
| Usability | First-time setup to working monitor in < 1 minute (single binary, no dependencies) | AC-NF13: Timed test with fresh user |

---

## 5. UI/UX Requirements

### 5.1 Main Window Layout

The main window consists of three panels. The top panel is a toolbar with a global speed indicator (aggregate upload/download), search bar for process filtering, and profile selector dropdown. The center panel is the process table, the primary view. The bottom panel is a collapsible chart area showing real-time speed graphs for the selected process.

The frontend is built with React + TypeScript inside Tauri's webview, communicating with the Rust backend via Tauri's IPC command system (`#[tauri::command]`). UI updates are pushed from Rust to the frontend via Tauri event emitting at 1-second intervals.

### 5.2 Process Table Columns

| Column | Content | Default Visible | Sortable |
|---|---|---|---|
| Icon + Name | Process icon and friendly name | Yes | Yes |
| PID | Process ID | No (toggle) | Yes |
| Download Speed | Current download in KB/s or MB/s (auto-scale) | Yes | Yes |
| Upload Speed | Current upload in KB/s or MB/s (auto-scale) | Yes | Yes |
| Total Downloaded | Cumulative bytes received since monitoring started | Yes | Yes |
| Total Uploaded | Cumulative bytes sent since monitoring started | Yes | Yes |
| Connections | Number of active TCP+UDP connections | Yes | Yes |
| DL Limit | Configured download speed limit (editable inline) | Yes | No |
| UL Limit | Configured upload speed limit (editable inline) | Yes | No |
| Blocked | Toggle switch to block/allow network access | Yes | No |

### 5.3 Interaction Patterns

- **Set limit:** Double-click the DL/UL Limit cell, type value in KB/s or MB/s, press Enter to apply
- **Remove limit:** Clear the limit cell or right-click and select "Remove Limit"
- **Block process:** Toggle the switch in the Blocked column
- **View details:** Click a row to expand the bottom chart panel with real-time speed graph for that process
- **Right-click context menu:** Set limit, block/unblock, view connections, copy process path, add to profile

---

## 6. Technology Stack (Rust)

| Component | Technology | License | Notes |
|---|---|---|---|
| Language | Rust (2021 edition, MSRV 1.75+) | MIT/Apache-2.0 | Zero-cost abstractions; no GC; single binary output |
| Async Runtime | `tokio` | MIT | Multi-threaded work-stealing scheduler for packet tasks |
| GUI Framework | Tauri v2 | MIT/Apache-2.0 | Rust backend + webview frontend; ~5MB overhead |
| Frontend | React + TypeScript + Tailwind | MIT | Inside Tauri webview; Recharts for graphs |
| Packet Capture (Win) | `windivert` crate + WinDivert 2.x | MIT (LGPL driver) | Safe Rust bindings; pre-signed driver; async support |
| Bandwidth Shaping (Mac) | pf + dnctl (built-in) | BSD | Kernel-level shaping; configure via `std::process::Command` |
| Process Info | `sysinfo` crate | MIT | Cross-platform PID, process name, exe path, CPU/mem |
| Concurrent Maps | `dashmap` | MIT | Lock-free concurrent HashMap for port-PID and traffic maps |
| Rate Limiting | `governor` crate or custom | MIT | Token bucket / leaky bucket with configurable burst |
| Database | `rusqlite` (SQLite) | MIT | Local storage for history & rules; bundled SQLite |
| Serialization | `serde` + `serde_json` | MIT/Apache-2.0 | Config files, IPC payloads, rule export/import |
| Logging | `tracing` + `tracing-subscriber` | MIT | Structured logging with per-module filtering |
| Error Handling | `anyhow` + `thiserror` | MIT/Apache-2.0 | Ergonomic error types for app vs library code |
| Testing | `cargo test` + `insta` (snapshots) | MIT | Unit, integration, and snapshot tests |
| Packaging (Win) | Tauri bundler → NSIS installer | — | .exe with UAC elevation manifest |
| Packaging (Mac) | Tauri bundler → .dmg | — | Native .app bundle with Info.plist |

### 6.1 Key Crate Versions (Pinned)

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
tauri = { version = "2", features = ["tray-icon", "notification"] }
windivert = "0.6"          # Windows only, behind cfg
sysinfo = "0.32"
dashmap = "6"
rusqlite = { version = "0.32", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
governor = "0.7"
tracing = "0.1"
anyhow = "1"
thiserror = "2"
nix = { version = "0.29", features = ["net"] }  # macOS only, behind cfg
```

### 6.2 Platform Conditional Compilation

```rust
// src/capture/mod.rs
#[cfg(target_os = "windows")]
mod windivert_backend;

#[cfg(target_os = "macos")]
mod pf_backend;

pub trait PacketBackend: Send + Sync {
    async fn start_capture(&self, filter: &str) -> Result<()>;
    async fn recv_packet(&self) -> Result<Packet>;
    async fn send_packet(&self, packet: Packet) -> Result<()>;
    fn set_rate_limit(&self, pid: u32, download: u64, upload: u64) -> Result<()>;
    fn block_process(&self, pid: u32, blocked: bool) -> Result<()>;
}
```

---

## 7. Development Phases

| Phase | Scope | Duration | Deliverable |
|---|---|---|---|
| Phase 1: Scaffold + Monitor | Project setup (Tauri + Rust workspace), F1 traffic monitor, Windows WinDivert SNIFF mode, basic React table | 2 weeks | Working Windows monitor with live process table |
| Phase 2: Rate Limiting | F2 bandwidth limiting, token bucket engine, async packet queue, WinDivert intercept mode | 2 weeks | Per-process throttling on Windows |
| Phase 3: macOS Port | Abstract `PacketBackend` trait, implement pf/dnctl backend, cross-compile testing | 2 weeks | Feature parity on macOS |
| Phase 4: Firewall + History | F3 connection blocking, F4 SQLite history + Recharts time-series, data pruning | 2 weeks | Full monitoring + control + analytics |
| Phase 5: Polish | F5 profiles, F6 system tray, F7 auto-start, Tauri bundling + installers, UX refinement | 2 weeks | Release-ready v1.0 |

---

## 8. Development Safety

This project operates at the kernel-network boundary. WinDivert intercept mode captures live packets — if the application panics, deadlocks, or fails to re-inject captured packets, **the host machine's network connectivity will be disrupted**. Docker/WSL2 cannot be used for development because WinDivert requires the native Windows kernel driver. All development and testing must occur directly on the host machine.

### 8.1 Risk Classification

| Scenario | Risk Level | Impact | Recovery |
|---|---|---|---|
| SNIFF mode (monitor only) | None | Packets are copied, never intercepted; network unaffected | N/A |
| Intercept mode — clean crash (panic + process exit) | Medium | Network drops for 1–3 seconds until WinDivert driver detects process exit and releases packets | Automatic |
| Intercept mode — deadlock (process hangs, no exit) | High | Network frozen indefinitely; captured packets held in kernel buffer | Manual: force-kill process or reboot |
| Intercept mode — broad filter + infinite loop | High | All network traffic frozen; cannot use network to debug | Manual: force-kill from local terminal or reboot |
| macOS pf misconfiguration | Medium | Firewall rules may block unintended traffic | Run `sudo pfctl -F all` to flush all rules |

### 8.2 Mandatory Development Safeguards

**S1 — Phased Capture Mode Progression**

All development MUST follow this capture mode progression. Do not skip phases:

| Dev Phase | Capture Mode | Filter Scope | Risk |
|---|---|---|---|
| Phase 1 (Monitor) | `WinDivertFlags::SNIFF` | `"tcp or udp"` (all traffic OK) | Zero — read-only copy |
| Phase 2a (Throttle prototype) | `WinDivertFlags::default()` (intercept) | Single test port only, e.g., `"tcp.DstPort == 5201"` | Low — only test traffic affected |
| Phase 2b (Throttle expansion) | Intercept | Specific process ports | Medium — one app affected |
| Phase 2c (Throttle production) | Intercept | `"tcp or udp"` (all traffic) | High — full network at risk |

**S2 — Narrow Filter-First Testing**

When developing intercept features, ALWAYS use the narrowest possible WinDivert filter. Use a dedicated test tool (e.g., iperf3 on port 5201) as the sole intercept target:

```rust
// ✅ SAFE: Only intercept iperf3 test traffic
WinDivert::new("tcp.DstPort == 5201 or tcp.SrcPort == 5201", ...)?;

// ❌ DANGEROUS during development: Intercepts ALL traffic
WinDivert::new("tcp or udp", ...)?;
```

**S3 — Watchdog Process**

A watchdog script MUST run in a separate terminal during all intercept-mode development. The watchdog monitors the main process and force-kills it if unresponsive:

```powershell
# watchdog.ps1 — run in separate terminal
param([int]$TimeoutSeconds = 10)
while ($true) {
    $proc = Get-Process -Name "netguard" -ErrorAction SilentlyContinue
    if ($proc) {
        $handle = $proc.Handle  # force refresh
        if (!$proc.Responding) {
            Write-Host "[WATCHDOG] NetGuard unresponsive, killing..."
            Stop-Process -Force -Name "netguard"
        }
    }
    Start-Sleep -Seconds 5
}
```

macOS equivalent:

```bash
#!/bin/bash
# watchdog.sh
while true; do
    PID=$(pgrep -x netguard)
    if [ -n "$PID" ] && ! kill -0 "$PID" 2>/dev/null; then
        echo "[WATCHDOG] NetGuard unresponsive, killing..."
        kill -9 "$PID"
        sudo pfctl -F all  # flush any leftover pf rules
    fi
    sleep 5
done
```

**S4 — Graceful Drop Handler**

The `CaptureEngine` struct MUST implement `Drop` to ensure WinDivert handles are released on any exit path (including panics during stack unwinding):

```rust
impl Drop for CaptureEngine {
    fn drop(&mut self) {
        // WinDivert handle drop releases the driver;
        // kernel automatically re-injects any buffered packets
        tracing::warn!("CaptureEngine dropped — releasing WinDivert handle");
    }
}
```

Additionally, set a custom panic hook to log before unwinding:

```rust
std::panic::set_hook(Box::new(|info| {
    tracing::error!("PANIC in NetGuard: {info}");
    // Stack unwinding will trigger Drop on CaptureEngine
}));
```

**S5 — Backup Network Connectivity**

During intercept-mode development, the developer MUST have an alternative network path available (mobile hotspot, secondary NIC, or Ethernet fallback) in case the primary network is disrupted by a bug.

**S6 — Emergency Recovery Procedures**

If the network is frozen and the application is unresponsive:

| Platform | Recovery Steps |
|---|---|
| Windows | 1. Open local PowerShell (no network needed). 2. `Stop-Process -Force -Name netguard`. 3. If WinDivert driver is stuck: `sc stop WinDivert14` (admin). 4. Last resort: reboot. |
| macOS | 1. Open local terminal. 2. `kill -9 $(pgrep netguard)`. 3. `sudo pfctl -F all` to flush pf rules. 4. `sudo dnctl -f flush` to remove dummynet pipes. 5. Last resort: reboot. |

### 8.3 Development Safety Acceptance Criteria

| AC ID | Criteria | Verification Method |
|---|---|---|
| AC-DS1 | SNIFF mode causes zero packet loss and zero added latency on the host | Automated: Run iperf3 baseline vs with SNIFF mode active, compare |
| AC-DS2 | Panic in intercept mode releases WinDivert handle and restores network within 5 seconds | Automated: Inject deliberate panic, measure network recovery time |
| AC-DS3 | Watchdog script successfully kills a hung NetGuard process within 10 seconds | Manual: Simulate hang (sleep loop), verify watchdog kills it |
| AC-DS4 | Narrow filter intercept mode does not affect traffic outside the filter scope | Automated: Intercept port 5201, verify port 80/443 traffic unaffected |
| AC-DS5 | macOS pf rule cleanup on exit leaves no residual firewall rules | Automated: Start/stop app, run `pfctl -sr` and `dnctl list`, verify clean |
| AC-DS6 | Emergency recovery procedures documented and tested on both platforms | Manual: Follow each step in recovery table, verify network restored |

---

## 9. Risks & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| WinDivert driver blocked by antivirus | High — app non-functional | Medium | Document AV exclusion steps; sign the exe with a code-signing cert |
| macOS SIP restricts pf configuration | High — no throttling on Mac | Low | Use Network Extension API as fallback; test on latest macOS betas |
| `windivert` crate API instability | Medium — breaking changes | Low | Pin version; fork crate if unmaintained; fallback to raw FFI |
| Tauri webview performance for rapid table updates | Medium — janky UI | Medium | Virtualize table rows (react-window); throttle updates to 1/sec; batch state diffs |
| Process exits before port mapping resolves | Low — minor accounting gap | High | Use kernel-level PID tagging where possible; accept small inaccuracy |
| `sysinfo` crate slow on macOS for port-PID resolution | Medium — high CPU | Medium | Cache aggressively (500ms TTL); use `libproc` FFI directly as fallback |
| Cross-compilation complexity (Win ↔ Mac) | Medium — CI burden | Medium | Use GitHub Actions with platform-specific runners; never cross-compile Tauri |
| Network disruption during intercept-mode development | High — developer loses connectivity | High | Mandatory phased progression (S1); narrow filters (S2); watchdog (S3); backup network (S5) |
| Residual pf/dnctl rules after macOS crash | Medium — unintended traffic blocking | Medium | Drop handler flushes rules (S4); emergency recovery documented (S6) |
| WinDivert handle leak on panic (no re-inject) | High — network frozen | Medium | Rust `Drop` impl on CaptureEngine (S4); watchdog auto-kills (S3) |

---

## 10. Out of Scope (v1.0)

- Deep packet inspection (DPI) or application-layer protocol analysis
- Remote management or multi-device monitoring
- VPN or proxy integration
- Linux support (potential v2.0 scope using tc + cgroups + eBPF)
- Per-connection (as opposed to per-process) bandwidth rules
- Bandwidth scheduling (time-based rules)
- Cloud sync of profiles or settings
- Mobile companion app

---

## 11. Acceptance Criteria Master Checklist

| ID | Feature | Criteria Summary | Priority |
|---|---|---|---|
| AC-1.1 | F1 Monitor | Process list matches netstat within 3s of launch | P0 |
| AC-1.2 | F1 Monitor | Speed accuracy within ±10% vs Wireshark | P0 |
| AC-1.3 | F1 Monitor | Cumulative bytes within 1% over 5 min | P0 |
| AC-1.4 | F1 Monitor | Column sorting works without data disruption | P0 |
| AC-1.5 | F1 Monitor | New process detected < 2s; removed < 5s | P0 |
| AC-1.6 | F1 Monitor | Process icons resolved for >95% standard apps | P0 |
| AC-2.1 | F2 Limiter | 500 KB/s limit yields 450–550 KB/s actual | P0 |
| AC-2.2 | F2 Limiter | Limit effective within 2s of application | P0 |
| AC-2.3 | F2 Limiter | Full speed restored within 1s of limit removal | P0 |
| AC-2.4 | F2 Limiter | 5+ simultaneous limits without cross-interference | P0 |
| AC-2.5 | F2 Limiter | Works for both TCP and UDP | P0 |
| AC-2.6 | F2 Limiter | No crash/leak after 100 rapid toggle cycles | P0 |
| AC-3.1 | F3 Firewall | Blocking prevents all new outbound TCP connections | P1 |
| AC-3.2 | F3 Firewall | Blocking one process doesn't affect others | P1 |
| AC-3.3 | F3 Firewall | Unblock restores access within 1s | P1 |
| AC-3.4 | F3 Firewall | DNS queries also blocked for blocked process | P1 |
| AC-4.1 | F4 History | Data persists across restarts | P1 |
| AC-4.2 | F4 History | 5-second granularity chart for last hour | P1 |
| AC-4.3 | F4 History | Correct ranking of top consumers | P1 |
| AC-4.4 | F4 History | DB size < 500 MB after 30 days | P1 |
| AC-4.5 | F4 History | Auto-prune data older than 90 days | P1 |
| AC-5.1 | F5 Profiles | Save/load profile with 10+ rules | P2 |
| AC-5.2 | F5 Profiles | Profile switch applies rules within 3s | P2 |
| AC-5.3 | F5 Profiles | Profiles persist across restarts | P2 |
| AC-6.1 | F6 Tray | Close window minimizes to tray | P1 |
| AC-6.2 | F6 Tray | Tray tooltip shows aggregate speed | P1 |
| AC-6.3 | F6 Tray | Right-click shows top 5 consumers | P1 |
| AC-6.4 | F6 Tray | Threshold notification within 5s | P1 |
| AC-7.1 | F7 AutoStart | Starts on login when enabled | P2 |
| AC-7.2 | F7 AutoStart | Persistent rules applied within 5s | P2 |
| AC-7.3 | F7 AutoStart | Rules match by exe path, not PID | P2 |
| AC-NF1 | Performance | CPU < 2% during monitoring only | P0 |
| AC-NF2 | Performance | CPU < 5% with 5 active throttles | P0 |
| AC-NF3 | Performance | Added latency < 0.5ms in SNIFF mode | P0 |
| AC-NF4 | Memory | RSS < 30 MB normal operation | P0 |
| AC-NF5 | Memory | RSS growth < 5 MB over 24 hours | P0 |
| AC-NF6 | Reliability | Crash doesn't disrupt network (fail-open) | P0 |
| AC-NF7 | Reliability | Handles 100 processes/sec creation rate | P0 |
| AC-NF8 | Security | Zero outbound traffic from NetGuard | P0 |
| AC-NF9 | Compatibility | Full pass on Windows 11 22H2+ | P0 |
| AC-NF10 | Compatibility | Full pass on macOS 13+ (Intel + ARM) | P0 |
| AC-NF11 | Binary Size | Installer < 15 MB | P1 |
| AC-NF12 | Startup | Cold start to operational < 3 seconds | P1 |
| AC-NF13 | Usability | Setup to working monitor < 1 minute | P1 |
| AC-DS1 | Dev Safety | SNIFF mode causes zero packet loss and zero added latency | P0 |
| AC-DS2 | Dev Safety | Panic in intercept mode restores network within 5s | P0 |
| AC-DS3 | Dev Safety | Watchdog kills hung process within 10s | P0 |
| AC-DS4 | Dev Safety | Narrow filter does not affect out-of-scope traffic | P0 |
| AC-DS5 | Dev Safety | macOS pf cleanup leaves no residual rules | P0 |
| AC-DS6 | Dev Safety | Emergency recovery procedures tested on both platforms | P0 |

---

## 12. Glossary

| Term | Definition |
|---|---|
| WinDivert | Open-source user-mode packet capture and re-injection library for Windows |
| pf | Packet Filter, the BSD-derived firewall built into macOS |
| dnctl / dummynet | Traffic shaping subsystem in macOS that provides pipe-based bandwidth limiting |
| Token Bucket | Rate limiting algorithm that permits burst traffic up to a configurable limit while enforcing a sustained rate ceiling |
| Tauri | Framework for building desktop apps with a Rust backend and web-based frontend, using the OS native webview |
| DashMap | A concurrent, lock-free HashMap implementation for Rust |
| tokio | Asynchronous runtime for Rust, providing multi-threaded task scheduling, timers, and I/O |
| `sysinfo` | Rust crate providing cross-platform system and process information |
| BPF | Berkeley Packet Filter, a low-level packet filtering language used by WinDivert and others |
| PID | Process Identifier, a unique numeric ID assigned by the OS to each running process |
| RSS | Resident Set Size, the portion of a process's memory held in physical RAM |
| SIP | System Integrity Protection, a macOS security feature restricting system-level modifications |
| SNIFF mode | WinDivert mode that copies packets for inspection without intercepting them |
| IPC | Inter-Process Communication; in Tauri, the mechanism for Rust ↔ JavaScript message passing |
| MSRV | Minimum Supported Rust Version |
