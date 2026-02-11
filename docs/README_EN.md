# NetGuard

Windows desktop application for monitoring per-process network traffic and controlling bandwidth.

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
| Packet Capture | WinDivert 2.x (SNIFF + INTERCEPT modes) |
| Database | SQLite (rusqlite, WAL mode) |
| Testing | cargo test (43 tests), Vitest (31 tests) |

## Prerequisites

- **Windows 11** 22H2+
- **Rust** 1.75+ (`rustup` stable toolchain)
- **Node.js** 18+ with npm
- **MSVC Build Tools**
- **Administrator privileges** at runtime (required for packet capture)

## Getting Started

```bash
# Install frontend dependencies
npm install

# Run in development mode (requires admin)
npm run tauri dev

# Run tests
cd src-tauri && cargo test    # 43 Rust unit tests
npm test                       # 31 frontend unit tests

# Build production installer
npm run tauri build
```

## Project Structure

```
NetGuard/
├── .github/workflows/       # CI pipeline
├── src/                     # React frontend (TypeScript + Tailwind)
├── src-tauri/               # Rust backend
│   ├── src/
│   │   ├── capture/         # Packet capture engine (WinDivert)
│   │   ├── core/            # Traffic accounting, token bucket rate limiter, process mapper
│   │   ├── db/              # SQLite history & rules storage
│   │   ├── commands.rs      # Tauri IPC commands
│   │   ├── lib.rs           # Tauri Builder + background thread startup
│   │   └── main.rs          # Entry point
│   └── vendor/windivert/    # Pre-built WinDivert (DLL + SYS + LIB)
├── scripts/                 # Safety scripts (watchdog + emergency recovery)
├── docs/                    # PRD, English README, refactor plan
└── public/                  # Static assets
```

## Architecture

Three-layer design:

1. **Packet Interception** — WinDivert 2.x user-space packet capture/re-injection with signed kernel driver
2. **Core Logic** — Rust: lock-free traffic accounting (DashMap), token bucket rate limiter, process-to-port mapping (sysinfo + Windows API)
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
- **Watchdog script** — `scripts/watchdog.ps1` auto-kills hung processes
- **Emergency recovery** — `scripts/emergency-recovery.ps1` for one-shot network restore
- **Phased capture progression** — Development follows mandatory SNIFF -> narrow filter -> full intercept phases

See [NetGuard_PRD_v1.0.md](NetGuard_PRD_v1.0.md) Section 8 for detailed safety protocols.

## Disclaimer

This software is intended for **legitimate use on devices you own or have explicit authorization to manage**. Examples include monitoring your own workstation's bandwidth, prioritizing traffic on a home network, or testing applications you develop.

The authors do not condone and are not responsible for any misuse of this software, including but not limited to unauthorized network interception, circumventing security controls, or violating applicable laws. **Use at your own risk.** The software is provided "as is", without warranty of any kind.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for details.

### Third-Party Components

This project includes [WinDivert](https://reqrypt.org/windivert.html), which is licensed under the **GNU Lesser General Public License v3 (LGPLv3)**. WinDivert is dynamically loaded at runtime; the rest of NetGuard remains under the Apache 2.0 license. See the WinDivert [LICENSE](https://github.com/basil00/WinDivert/blob/master/LICENSE) for details.
