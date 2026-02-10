# NetGuard

Cross-platform desktop application for monitoring per-process network traffic and controlling bandwidth on Windows 11 and macOS.

## Features

- **Real-time process monitor** — Live table of all processes with active network connections, showing upload/download speeds, cumulative bytes, and connection count
- **Per-process bandwidth limiting** — Set independent upload/download speed limits for any process using Token Bucket rate limiting
- **Per-process firewall** — Block/unblock network access for individual applications
- **Traffic history** — SQLite-backed historical charts with per-process bandwidth trends
- **Rule profiles** — Save and switch between named sets of bandwidth rules (e.g. "Gaming Mode")
- **System tray** — Background monitoring with quick-access tray menu and threshold notifications

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Rust, Tokio, DashMap |
| Framework | Tauri v2 |
| Frontend | React, TypeScript, Tailwind CSS, Recharts |
| Packet Capture (Windows) | WinDivert 2.x |
| Bandwidth Shaping (macOS) | pf + dnctl/dummynet |
| Database | SQLite (rusqlite) |

## Prerequisites

- **Rust** 1.75+ (`rustup` stable toolchain)
- **Node.js** 18+ with npm
- **MSVC Build Tools** (Windows) or **Xcode CLI Tools** (macOS)
- **Administrator/root privileges** at runtime (required for packet capture)

## Getting Started

```bash
# Install frontend dependencies
npm install

# Run in development mode
npm run tauri dev

# Build production installer
npm run tauri build
```

## Architecture

Three-layer design:

1. **Packet Interception** — Platform-specific backends behind a common `PacketBackend` trait
   - Windows: WinDivert (user-space kernel driver)
   - macOS: pf/dnctl (built-in firewall + traffic shaper)
2. **Core Logic** — Cross-platform Rust: traffic accounting, token bucket rate limiter, process-to-port mapping
3. **Frontend** — React + Tailwind in Tauri webview, communicating via IPC commands and events

## Safety

This application intercepts live network packets. Development follows a mandatory phased progression from read-only SNIFF mode to full intercept mode. See `docs/NetGuard_PRD_v1.0.md` Section 8 for detailed safety protocols.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
