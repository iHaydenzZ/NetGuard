# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NetGuard is a Windows desktop application for monitoring per-process network traffic and controlling bandwidth. Built with Rust (backend) + Tauri v2 (framework) + React/TypeScript/Tailwind (frontend). The full PRD is at `docs/NetGuard_PRD_v1.0.md`.

**Current status:** All features (F1-F7) implemented on Windows. SNIFF mode active by default; intercept mode available via Settings toggle ("Enforce limits"). 43 Rust + 31 frontend tests passing. AC-1.6 process icons, context menu, PID toggle, live speed chart, watchdog scripts all done.

## Development Philosophy

- **Iterate:** Make it work → Make it right → Make it fast. Never all three at once.
- Hard-code first, abstract later. Small, frequent commits — one logical change each.
- Follow standard SOLID/YAGNI/DRY principles. Apply design patterns during refactoring, not on first draft.
- Structure code as pipelines (Ingest → Process → Output). Separate I/O from core logic.
- Use `tracing` for structured logging (not `println!`). Externalize config — no magic numbers.

## Design Invariants

- **Fail-open:** If the app crashes, all traffic flows normally
- **Non-destructive default:** Monitor-only; throttling requires explicit user action
- **Minimal footprint:** <2% CPU monitoring, <5% with 5 throttles, <30MB RSS
- **Zero runtime dependency:** Single binary distribution

## Architecture

Three-layer design:

1. **Packet Interception Layer** — WinDivert 2.x via `windivert` crate — user-space packet capture/re-injection with signed kernel driver

2. **Core Logic Layer** (Rust)
   - Traffic accounting: `tokio` async runtime + `DashMap` for lock-free concurrent counters
   - Rate limiting: Token Bucket algorithm (`governor` crate) — per-process, independent up/down limits
   - Process mapping: `sysinfo` crate for port-to-PID resolution

3. **Frontend Layer** (Tauri webview)
   - React + TypeScript + Tailwind in Tauri's webview
   - Rust→JS communication via Tauri IPC (`#[tauri::command]` + event emitting at 1s intervals)
   - Recharts for real-time speed graphs

### Concurrency Model

```
Main Thread (Tauri event loop / UI)
  ├── Packet Capture Task (tokio::spawn) → recv loop → classify → route to per-process channel
  ├── Per-Process Throttle Tasks (tokio::spawn, one per limited process) → mpsc → token bucket → send
  ├── Stats Aggregator Task (1s tick) → DashMap<PID, TrafficCounters> → compute speeds → emit to frontend
  └── Process Scanner Task (500ms tick) → sysinfo refresh → update port-PID map
```

All packet-path operations are lock-free via `DashMap`. The `tokio` work-stealing runtime ensures the capture loop never blocks on UI or DB.

## Build Commands

```bash
# Development
npm install                    # Install frontend dependencies (first time)
npm run tauri dev              # Run full app in dev mode (builds Rust + starts Vite)

# Rust only
cd src-tauri
cargo check                    # Fast type-check without full build
cargo build                    # Full debug build
cargo test                     # Run unit tests
cargo clippy                   # Lint
cargo fmt                      # Format code

# Frontend only
npm run dev                    # Vite dev server (no Tauri)
npm run build                  # Production frontend build

# Production
npm run tauri build            # Create Windows installer
```

## Project Structure

```
NetGuard/
├── .github/
│   └── workflows/
│       └── ci.yml                   # GitHub Actions CI pipeline
├── package.json                     # Frontend deps + Tauri CLI scripts
├── package-lock.json                # npm lockfile
├── vite.config.ts                   # Vite + React + Tailwind plugins
├── vitest.config.ts                 # Frontend test configuration
├── tsconfig.json                    # TypeScript config
├── tsconfig.node.json               # TypeScript config for Node tooling
├── index.html                       # Vite entry HTML
├── LICENSE                          # Apache 2.0
├── src/                             # React frontend
│   ├── main.tsx                     # React entry point
│   ├── App.tsx                      # Composition root (≤100 lines)
│   ├── bindings.ts                  # Auto-generated TypeScript types (ts-rs)
│   ├── utils.ts                     # Shared utility functions (formatSpeed, formatBytes, etc.)
│   ├── utils.test.ts                # Vitest unit tests (31 tests)
│   ├── styles.css                   # Tailwind CSS entry (@import "tailwindcss")
│   ├── vite-env.d.ts                # Vite client type declarations
│   ├── components/                  # UI components
│   │   ├── Header.tsx               # App header with speed summary + filter
│   │   ├── ProcessTable.tsx         # Process table with sorting, filtering, inline editing
│   │   ├── HistoryChart.tsx         # Traffic history chart + top consumers
│   │   ├── LiveSpeedChart.tsx       # 60-second live speed chart
│   │   ├── ChartPanel.tsx           # Chart panel container (live + history modes)
│   │   ├── SettingsPanel.tsx        # Settings panel (threshold, autostart, intercept)
│   │   ├── ProfileBar.tsx           # Profile management bar
│   │   ├── ContextMenu.tsx          # Right-click context menu
│   │   ├── StatusBar.tsx            # Bottom status bar
│   │   └── ui/                      # Atomic UI components
│   │       ├── Toggle.tsx           # Toggle switch
│   │       ├── Badge.tsx            # Status badge
│   │       ├── Th.tsx               # Sortable table header cell
│   │       ├── LimitCell.tsx        # Inline-editable limit cell
│   │       ├── CtxItem.tsx          # Context menu item
│   │       └── SettingToggle.tsx    # Label + Toggle combo
│   └── hooks/                       # Custom React hooks
│       ├── useTrafficData.ts        # Traffic data + limits + blocking state
│       ├── useProfiles.ts           # Profile CRUD operations
│       ├── useSettings.ts           # Notification, autostart, intercept state
│       └── useChartData.ts          # History chart data loading
├── public/                          # Static assets
│   ├── tauri.svg
│   └── vite.svg
├── scripts/                         # Safety scripts (PRD S3, S6)
│   ├── watchdog.ps1                 # Auto-kill hung NetGuard (AC-DS3)
│   └── emergency-recovery.ps1      # One-shot network restore (AC-DS6)
├── docs/
│   ├── NetGuard_PRD_v1.0.md         # Full product requirements document
│   ├── README_EN.md                 # English README
│   └── Refactor_Plan.md             # Codebase maintainability improvement plan
└── src-tauri/
    ├── Cargo.toml                   # Rust deps (windivert vendored)
    ├── Cargo.lock                   # Rust dependency lockfile
    ├── build.rs                     # Tauri build script
    ├── tauri.conf.json              # Tauri app config
    ├── tauri.windows.conf.json      # Windows-specific Tauri config overrides
    ├── .cargo/
    │   └── config.toml              # Cargo build configuration (linker settings)
    ├── capabilities/
    │   └── default.json             # Tauri v2 capability permissions
    ├── icons/                       # App icons (16 sizes for Windows)
    ├── vendor/
    │   └── windivert/
    │       ├── WinDivert.dll        # WinDivert runtime library
    │       ├── WinDivert.lib        # WinDivert import library
    │       └── WinDivert64.sys      # WinDivert kernel driver (signed)
    └── src/
        ├── main.rs                  # Binary entry → calls netguard_lib::run()
        ├── lib.rs                   # Tauri Builder setup (≤40 line setup closure)
        ├── error.rs                 # AppError unified error type
        ├── config.rs                # Centralized runtime constants
        ├── services.rs              # BackgroundServices lifecycle management
        ├── commands/
        │   ├── mod.rs               # pub use re-exports + AppState
        │   ├── state.rs             # AppState struct definition
        │   ├── traffic.rs           # F1 monitoring + F4 history + icons
        │   ├── rules.rs             # F2 limiting + F3 blocking + F5 profiles
        │   ├── system.rs            # F6 notifications + F7 autostart + intercept
        │   └── logic.rs             # Pure business logic (unit-testable)
        ├── capture/
        │   ├── mod.rs               # CaptureEngine + packet parsing
        │   └── windivert_backend.rs # WinDivert SNIFF + INTERCEPT loops
        ├── core/
        │   ├── mod.rs               # pub use re-exports
        │   ├── traffic.rs           # TrafficTracker with DashMap
        │   ├── rate_limiter.rs      # Token bucket per process
        │   ├── process_mapper.rs    # PID ↔ port mapping (slim)
        │   ├── icon_extractor.rs    # Win32 icon extraction + BMP encoding
        │   └── win_net_table.rs     # iphlpapi FFI (TCP/UDP tables)
        └── db/
            ├── mod.rs               # Database struct + connection + types
            ├── history.rs           # traffic_history table CRUD
            └── rules.rs             # bandwidth_rules table CRUD
```

## Key Dependencies (Pinned Versions)

**Rust:** tokio 1.x (full), tauri 2.x, windivert 0.6, sysinfo 0.32, dashmap 6.x, rusqlite 0.32 (bundled), governor 0.7, serde 1.x, tracing 0.1, anyhow 1.x, thiserror 2.x, base64 0.22

**Frontend:** React, TypeScript, Tailwind CSS, Recharts, Vitest (testing)

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

`Stop-Process -Force -Name netguard` → if driver stuck: `sc stop WinDivert14`

## Dev Setup

### Running with Elevated Privileges

Packet capture requires admin. During development:
Right-click terminal → "Run as administrator", then `npm run tauri dev`

### Test Tools

- **iperf3:** Bandwidth testing target (port 5201). Install via `winget install iperf3`. Run server: `iperf3 -s`
- **Wireshark:** Baseline packet verification. Install from https://www.wireshark.org/

### Dev Server

Vite runs on `localhost:1420` (configured in `src-tauri/tauri.conf.json`). HMR port: 1421.

## Environment Constraints

- **Cannot use Docker, WSL2, or VMs** — WinDivert requires the native Windows kernel driver
- **Requires admin at runtime** — packet capture needs elevated privileges
- **Must develop on Windows 11** 22H2+
- **Keep backup network available** (mobile hotspot) during intercept-mode development
- **Test tools needed:** iperf3 (bandwidth testing), Wireshark (baseline verification)

## Error Handling Conventions

- `anyhow` for application-level errors (binary crate)
- `thiserror` for typed errors in library code
- `tracing` for structured logging with per-module filtering

## Additional

- Don't ask me questions; make your own decisions and move forward. When you encounter uncertainties, read **'docs\NetGuard_PRD_v1.0.md'** to choose the most reasonable solution and continue.
- Double check the env of the developing computer to confirm it's a Windows computer, please use the corresponding command line.
- Commit after completing each several tasks.
