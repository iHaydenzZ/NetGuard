# NetGuard

Cross-platform desktop application for monitoring per-process network traffic and controlling bandwidth on Windows 11 and macOS.

## Features

- **Real-time process monitor** — Live table of all processes with active network connections, showing process icons, upload/download speeds, cumulative bytes, and connection count. Sortable columns, search/filter bar, and 1-second refresh.
- **Per-process bandwidth limiting** — Set independent upload/download speed limits for any process via inline editing or right-click context menu. Token Bucket algorithm with 2x burst allowance.
- **Per-process firewall** — Block/unblock network access for individual applications with a toggle switch. Blocked packets are silently dropped.
- **Traffic history & analytics** — SQLite-backed time-series charts (1h/24h/7d/30d) with per-process bandwidth trends and top consumers dashboard. Auto-prunes data older than 90 days.
- **Rule profiles** — Save and switch between named sets of bandwidth rules (e.g. "Gaming Mode", "Video Call Mode"). Profiles persist across restarts.
- **System tray** — Background monitoring with aggregate speed tooltip, top-5 consumers menu, and configurable bandwidth threshold notifications.
- **Auto-start & persistent rules** — Launch on login with automatic rule re-application to matching processes by executable path.
- **Live speed chart** — Click any process to see a real-time 60-second speed graph.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Rust, Tokio, DashMap |
| Framework | Tauri v2 |
| Frontend | React, TypeScript, Tailwind CSS, Recharts |
| Packet Capture (Windows) | WinDivert 2.x (SNIFF + INTERCEPT modes) |
| Bandwidth Shaping (macOS) | pf + dnctl/dummynet |
| Database | SQLite (rusqlite, WAL mode) |
| Testing | cargo test (43 tests), Vitest (31 tests) |

## Prerequisites

- **Rust** 1.75+ (`rustup` stable toolchain)
- **Node.js** 18+ with npm
- **MSVC Build Tools** (Windows) or **Xcode CLI Tools** (macOS)
- **Administrator/root privileges** at runtime (required for packet capture)

## Getting Started

```bash
# Install frontend dependencies
npm install

# Run in development mode (requires admin/root)
npm run tauri dev

# Run tests
cd src-tauri && cargo test    # 43 Rust unit tests
npm test                       # 31 frontend unit tests

# Build production installer
npm run tauri build
```

## Architecture

Three-layer design:

1. **Packet Interception** — Platform-specific backends behind conditional compilation (`#[cfg(target_os)]`)
   - Windows: WinDivert 2.x — user-space packet capture/re-injection with signed kernel driver
   - macOS: pf + dnctl — kernel-level traffic shaping via dummynet pipes
2. **Core Logic** — Cross-platform Rust: lock-free traffic accounting (DashMap), token bucket rate limiter, process-to-port mapping (sysinfo + Windows API / lsof)
3. **Frontend** — React + Tailwind in Tauri webview, communicating via IPC commands and 1-second event emitting

### Operating Modes

| Mode | Description | Risk |
|------|-------------|------|
| SNIFF (default) | Read-only packet copies for monitoring | Zero |
| INTERCEPT (opt-in) | Captures and re-injects packets for rate limiting/blocking | Requires admin |

INTERCEPT mode is activated via the "Enforce limits" toggle in Settings. Without it, rate limits and blocks are visual only.

## Safety

This application intercepts live network packets. A bug in intercept mode can disrupt the host machine's network connectivity.

- **Fail-open design** — If the app crashes, all traffic flows normally (WinDivert handles released via `Drop` trait)
- **Watchdog scripts** — `scripts/watchdog.ps1` (Windows) / `scripts/watchdog.sh` (macOS) auto-kill hung processes
- **Emergency recovery** — `scripts/emergency-recovery.ps1` / `scripts/emergency-recovery.sh` for one-shot network restore
- **Phased capture progression** — Development follows mandatory SNIFF -> narrow filter -> full intercept phases

See `docs/NetGuard_PRD_v1.0.md` Section 8 for detailed safety protocols.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
