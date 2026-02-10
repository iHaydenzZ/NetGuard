# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NetGuard is a cross-platform desktop application (Windows 11 + macOS) for monitoring per-process network traffic and controlling bandwidth. Built with Rust (backend) + Tauri v2 (framework) + React/TypeScript/Tailwind (frontend). The full PRD is at `docs/NetGuard_PRD_v1.0.md`.

**Current status:** Pre-development — only the PRD exists. No source code, build system, or git repo has been created yet.

## Architecture

Three-layer design:

1. **Packet Interception Layer** (platform-specific)
   - Windows: WinDivert 2.x via `windivert` crate — user-space packet capture/re-injection with signed kernel driver
   - macOS: Built-in pf (Packet Filter) + dnctl/dummynet via `std::process::Command` subprocess calls

2. **Core Logic Layer** (cross-platform Rust)
   - Traffic accounting: `tokio` async runtime + `DashMap` for lock-free concurrent counters
   - Rate limiting: Token Bucket algorithm (`governor` crate) — per-process, independent up/down limits
   - Process mapping: `sysinfo` crate for port-to-PID resolution

3. **Frontend Layer** (Tauri webview)
   - React + TypeScript + Tailwind in Tauri's webview
   - Rust→JS communication via Tauri IPC (`#[tauri::command]` + event emitting at 1s intervals)
   - Recharts for real-time speed graphs

### Cross-Platform Abstraction

Platform backends implement a common `PacketBackend` trait using conditional compilation:

```rust
#[cfg(target_os = "windows")]  mod windivert_backend;
#[cfg(target_os = "macos")]    mod pf_backend;

pub trait PacketBackend: Send + Sync {
    async fn start_capture(&self, filter: &str) -> Result<()>;
    async fn recv_packet(&self) -> Result<Packet>;
    async fn send_packet(&self, packet: Packet) -> Result<()>;
    fn set_rate_limit(&self, pid: u32, download: u64, upload: u64) -> Result<()>;
    fn block_process(&self, pid: u32, blocked: bool) -> Result<()>;
}
```

### Concurrency Model

```
Main Thread (Tauri event loop / UI)
  ├── Packet Capture Task (tokio::spawn) → recv loop → classify → route to per-process channel
  ├── Per-Process Throttle Tasks (tokio::spawn, one per limited process) → mpsc → token bucket → send
  ├── Stats Aggregator Task (1s tick) → DashMap<PID, TrafficCounters> → compute speeds → emit to frontend
  └── Process Scanner Task (500ms tick) → sysinfo refresh → update port-PID map
```

All packet-path operations are lock-free via `DashMap`. The `tokio` work-stealing runtime ensures the capture loop never blocks on UI or DB.

## Planned Build Commands

```bash
# Development
cargo build                    # Build Rust backend
npm install                    # Install frontend dependencies
npm run tauri dev              # Run full app in dev mode

# Testing
cargo test                     # Rust unit tests
cargo clippy                   # Lint Rust code
npm test                       # Frontend tests

# Production
npm run tauri build            # Create platform-specific installers
```

## Planned Project Structure

```
NetGuard/
├── Cargo.toml                    # Rust workspace root
├── src-tauri/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── capture/
│       │   ├── mod.rs            # PacketBackend trait + dispatch
│       │   ├── windivert_backend.rs  # Windows (cfg-gated)
│       │   └── pf_backend.rs     # macOS (cfg-gated)
│       ├── core/
│       │   ├── traffic.rs        # Traffic accounting with DashMap
│       │   ├── rate_limiter.rs   # Token bucket per process
│       │   └── process_mapper.rs # PID ↔ port mapping via sysinfo
│       ├── db/
│       │   └── sqlite.rs         # rusqlite history + rules storage
│       └── commands.rs           # Tauri IPC command handlers
├── src/                          # React frontend
│   ├── App.tsx
│   └── components/
│       ├── ProcessTable.tsx
│       ├── SpeedChart.tsx
│       └── SystemTray.tsx
├── public/
└── docs/
    └── NetGuard_PRD_v1.0.md
```

## Key Dependencies (Pinned Versions)

**Rust:** tokio 1.x (full), tauri 2.x, windivert 0.6 (Windows-only), sysinfo 0.32, dashmap 6.x, rusqlite 0.32 (bundled), governor 0.7, serde 1.x, tracing 0.1, anyhow 1.x, thiserror 2.x, nix 0.29 (macOS-only)

**Frontend:** React, TypeScript, Tailwind CSS, Recharts

**MSRV:** Rust 1.75+

## Critical: Development Safety

This project intercepts live network packets. A bug in intercept mode can freeze the host machine's network.

### Mandatory Capture Mode Progression (never skip phases)

| Phase | Mode | Filter | Risk |
|-------|------|--------|------|
| Phase 1 | `WinDivertFlags::SNIFF` (read-only copy) | `"tcp or udp"` | Zero |
| Phase 2a | Intercept | Single test port: `"tcp.DstPort == 5201"` | Low |
| Phase 2b | Intercept | Specific process ports | Medium |
| Phase 2c | Intercept | `"tcp or udp"` (all traffic) | High |

### Narrow Filter-First Rule

Always use the narrowest WinDivert filter possible during development. Target iperf3 (port 5201) first:
```rust
// SAFE: only test traffic
WinDivert::new("tcp.DstPort == 5201 or tcp.SrcPort == 5201", ...)?;
// DANGEROUS during development: all traffic
WinDivert::new("tcp or udp", ...)?;
```

### Watchdog Requirement

A watchdog script must run in a separate terminal during intercept-mode dev. It auto-kills hung processes within 10s. See PRD section 8.2 (S3) for scripts.

### CaptureEngine Must Implement Drop

The `Drop` trait on `CaptureEngine` is mandatory — ensures WinDivert handles are released on panic, preventing network freeze.

### Emergency Recovery

- **Windows:** `Stop-Process -Force -Name netguard` → if driver stuck: `sc stop WinDivert14`
- **macOS:** `kill -9 $(pgrep netguard)` → `sudo pfctl -F all` → `sudo dnctl -f flush`

## Environment Constraints

- **Cannot use Docker, WSL2, or VMs** — WinDivert requires the native Windows kernel driver
- **Requires admin/root at runtime** — packet capture needs elevated privileges
- **Must develop on native OS** — Windows 11 22H2+ for Windows features, macOS 13+ for macOS features
- **Keep backup network available** (mobile hotspot) during intercept-mode development
- **Test tools needed:** iperf3 (bandwidth testing), Wireshark (baseline verification)

## Development Phases

1. **Scaffold + Monitor** — Tauri + Rust workspace, F1 traffic monitor, WinDivert SNIFF mode, React table
2. **Rate Limiting** — F2 bandwidth limiting, token bucket engine, WinDivert intercept mode
3. **macOS Port** — Abstract PacketBackend trait, pf/dnctl backend, cross-platform testing
4. **Firewall + History** — F3 connection blocking, F4 SQLite history + Recharts charts
5. **Polish** — F5 profiles, F6 system tray, F7 auto-start, Tauri bundling + installers

## Design Principles

- **Fail-open:** If the app crashes, all traffic flows normally
- **Non-destructive default:** Monitor-only; throttling requires explicit user action
- **Minimal footprint:** <2% CPU monitoring, <5% with 5 throttles, <30MB RSS
- **Zero runtime dependency:** Single binary distribution
- **Cross-platform parity:** Core features identical on Windows and macOS despite different backends

## Error Handling Conventions

- `anyhow` for application-level errors (binary crate)
- `thiserror` for typed errors in library code
- `tracing` for structured logging with per-module filtering
