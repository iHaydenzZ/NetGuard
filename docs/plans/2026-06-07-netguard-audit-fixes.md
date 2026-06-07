# NetGuard Audit Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the confirmed safety, correctness, security-hardening, packaging, and documentation issues found in the June 2026 multi-angle audit.

**Architecture:** Treat this as long-lived code. Keep packet capture fail-open, process identity, and user-visible enforcement semantics as the main boundaries. Use small, independently committable fixes: first restore emergency recovery and INTERCEPT fail-open behavior, then correct enforcement identity/UI behavior, then harden packaging, CI, and test coverage.

**Tech Stack:** Rust 2021, Tauri v2, WinDivert 2.2.x, Windows IP Helper API, SQLite/rusqlite, React 19, TypeScript, Vitest, GitHub Actions

---

## Reviewer Notes — 修正项清单 (2026-06-08)

> 来源：对当前代码的逐文件复核（macOS 静态审查 + 多 agent 对抗验证）。本节仅为修正提示，**不改动下方任何任务步骤**；执行到对应任务时先按此处调整。整体结论：plan 方向、优先级与 TDD 纪律均正确，**可执行**。

### 🔴 执行前务必修正（否则会在 Windows 上直接踩坑）

- **Task 4 会让两个现有测试变红**，但 Step 6 写的是 "Expected: PASS"。引入 `MIN_PACKET_BURST_BYTES` 后，两个硬编码"2×rate 突发"的测试会失败，因为它们正编码了被修复的旧行为：
  - `test_should_drop_over_budget`（`rate_limiter.rs:436`，rate 1000 → 旧突发 2000，断言第 3 个包被 drop）
  - `test_should_pass_refills_after_drop`（`rate_limiter.rs:540`，rate 10000 → 旧突发 20000）
  → 在 Task 4 增加一步：更新这两个测试的期望值（或改写为验证"长期节流"而非固定 2× 突发）。

- **Task 3 修复不完整：fail-open break 后会"监控假死 + UI 说谎"。** `run_intercept_loop` break 后句柄关闭（流量恢复 ✅），但没有重启 SNIFF、也没有清空 `intercept_engine`：监控循环停止 → 监控静默失效；`is_intercept_active()` 仍返回 true → UI 仍显示 "Enforce limits: Active"。
  → 补应用层协调：拦截线程退出时回传信号（共享 flag / event），由 `services`/命令层 drop 掉 engine、重启 SNIFF，并 emit 事件把前端 `interceptActive` 置回 false。（这是 plan 对原 finding "revert to SNIFF" 未完成的部分；fail-open 本身已是净改进。）

- **Task 5 是风险最高、验证最弱的一项。** `LocalEndpoint` 的通配回退（精确 → `0.0.0.0:port` / `:::port`）是承重逻辑：监听套接字在 IP Helper 表里是通配地址，但真实数据包带具体本地地址；回退一旦写错会破坏**所有监听进程**的归属（比所修 bug 更糟）。当前只测了 v4/v6 区分，**没有**通配回退测试，也**没有**运行时冒烟步骤（不像 Task 3/4）。
  → 补：(1) 通配回退单测（具体地址包命中 `0.0.0.0` 表项）；(2) 运行时 before/after 校验——用真实流量确认常见应用归属与旧的纯端口行为一致后再信任。

### 🟡 较小修正

- **Task 14 Step 5**：`cargo update -p tauri-plugin-opener --precise 0.0.0` 是无效命令，删掉即可——移除依赖后 `cargo check` 会自动重写 `Cargo.lock`。另：`npm uninstall` 前先确认 `@tauri-apps/plugin-opener` 确为 `package.json` 直接依赖。
- **Task 10**：`get_process_info(pid).is_none()` 的"未知 PID"拦截，会在某进程刚出现于流量快照（回退名 `PID {n}`）但尚未进 `process_info` 的 ~500ms 窗口内误拒合法的 block；且当前前端会吞掉 block 报错。建议要么只拦 0/4/self，要么确保 Task 8/9 的错误提示覆盖 block 路径。
- **Task 11**："前端缓存仍按 exe_path"低估了改造量：需把现有按 path 去重的逻辑（`iconRequested`/`newPaths`）改为"每个 exe_path 选一个当前 PID → 按 PID 调用 → 按 path 存结果"。请在步骤里写清。
- **Task 13**：聚合语义偏含糊（`bytes_sent/recv` 是会话内累计、PID 变更即重置），分桶规则需明确定义；当前测试只断言 `len <= 10`，请补值正确性断言，并确认 `HistoryChart` 能渲染聚合后的形状。
- **Task 12**：测试只覆盖 helper 字符串，真正风险是 `reg.exe` 的 argv 引号往返。加运行时校验：切换 autostart 后检查 `HKCU\…\Run` 实际存的是带引号的路径。
- **Task 1**：静态改名为 `WinDivert` 对 2.2.2 极可能正确，`sc.exe query WinDivert` 冒烟即安全网。可考虑动态变体（`sc query type=driver state=all | Select-String WinDivert`，命中即停）作为额外保险。

### ⚪ Plan 未覆盖的一处 Medium

- **Loopback 流量**（127.0.0.1/::1 被捕获、计数、并在 intercept 下被节流；`windivert_backend.rs:27`）会虚增统计并可能自我节流本地 IPC。低成本修复：给 SNIFF 与默认 intercept filter 追加 `and not loopback`。请新增一个小任务或显式决定推迟。

### 关于"被有意省略"的项

本 plan **有意未包含**"拦截线程 panic / 托盘 Quit → 永久冻结"的 `catch_unwind` / `RunEvent::Exit` 修复——复核确认这些场景 fail-open 实际成立（panic 时线程持有的 `wd` 句柄随栈展开 drop、进程退出时 OS 关闭句柄，均触发驱动重注入）。请勿"顺手"把它们加回为高优任务；真正的冻结向量已由 Task 3/4 覆盖。

---

## Execution Notes

- Run implementation on Windows 11 22H2+ for all Rust/WinDivert validation. Packet capture and intercept-mode smoke tests require administrator privileges.
- Keep the watchdog running in a separate elevated PowerShell terminal before any INTERCEPT runtime test.
- Use TDD where practical: add the failing unit test first, run it, implement the minimal fix, rerun.
- Commit after each task. Do not batch unrelated changes.
- Do not auto-format or restyle files outside the task's touched files.
- Current audit verification from macOS was limited: frontend tests passed, but Rust/WinDivert runtime tests were not run.

---

## Phase 1: Release-Blocking Safety Fixes

### Task 1: Fix WinDivert Emergency Recovery Service Name

**Files:**
- Modify: `scripts/emergency-recovery.ps1:22-29`
- Modify: `scripts/watchdog.ps1:26-30`
- Modify: `CLAUDE.md:225`
- Modify: `docs/NetGuard_PRD_v1.0.md:428`

**Step 1: Update emergency recovery to stop the WinDivert 2.x service**

In `scripts/emergency-recovery.ps1`, replace:
```powershell
$result = sc.exe stop WinDivert14 2>&1
```
with:
```powershell
$result = sc.exe stop WinDivert 2>&1
```

**Step 2: Update watchdog fallback recovery**

In `scripts/watchdog.ps1`, replace:
```powershell
sc.exe stop WinDivert14 2>$null
```
with:
```powershell
sc.exe stop WinDivert 2>$null
```

**Step 3: Update recovery documentation**

Replace `sc stop WinDivert14` with `sc stop WinDivert` in:
- `CLAUDE.md`
- `docs/NetGuard_PRD_v1.0.md`

**Step 4: Verify text references**

Run:
```bash
rg -n "WinDivert14|sc stop WinDivert" scripts docs CLAUDE.md
```

Expected:
- No `WinDivert14` matches.
- Recovery docs reference `sc stop WinDivert`.

**Step 5: Windows smoke check**

In elevated PowerShell:
```powershell
sc.exe query WinDivert
```

Expected:
- If the driver is installed/running, the service query resolves to `SERVICE_NAME: WinDivert`.
- If the driver is not installed, the command may report missing service; that is acceptable before runtime use.

**Step 6: Commit**

```bash
git add scripts/emergency-recovery.ps1 scripts/watchdog.ps1 CLAUDE.md docs/NetGuard_PRD_v1.0.md
git commit -m "fix: correct WinDivert recovery service name"
```

---

### Task 2: Add WinDivert License Materials to Distribution

**Files:**
- Create: `src-tauri/vendor/windivert/LICENSE`
- Modify: `src-tauri/tauri.windows.conf.json:3-6`
- Modify: `src-tauri/build.rs:34-58`
- Modify: `README.md:121-123`
- Modify: `docs/README_EN.md:119-121`
- Modify: `docs/NetGuard_PRD_v1.0.md:58`
- Modify: `docs/NetGuard_PRD_v1.0.md:255`

**Step 1: Add the upstream WinDivert license**

Create `src-tauri/vendor/windivert/LICENSE` using the exact license text from the official WinDivert 2.2.2 package/source. Do not paraphrase it.

Expected license identity:
- WinDivert is LGPLv3/GPLv2 dual-licensed.
- NetGuard's own license remains Apache 2.0.

**Step 2: Package the license with Windows bundles**

In `src-tauri/tauri.windows.conf.json`, add the license as a bundle resource:
```json
"vendor/windivert/LICENSE": "./"
```

**Step 3: Copy the license next to debug/release binaries**

In `src-tauri/build.rs`, extend the Windows copy loop from:
```rust
for file in &["WinDivert.dll", "WinDivert64.sys"] {
```
to:
```rust
for file in &["WinDivert.dll", "WinDivert64.sys", "LICENSE"] {
```

Also add:
```rust
println!("cargo:rerun-if-changed=vendor/windivert/LICENSE");
```

**Step 4: Correct license documentation**

Update `README.md`, `docs/README_EN.md`, and `docs/NetGuard_PRD_v1.0.md` so all WinDivert license references consistently say LGPLv3/GPLv2 dual license. Remove PRD wording that calls WinDivert MIT-licensed.

**Step 5: Verify package-resource references**

Run:
```bash
rg -n "WinDivert.*MIT|MIT.*WinDivert|LGPL|GPLv2|vendor/windivert/LICENSE" README.md docs src-tauri
```

Expected:
- No PRD/README claim that WinDivert itself is MIT.
- The vendored license path is referenced by package/build config.

**Step 6: Build verification on Windows**

Run:
```powershell
npm run tauri build
```

Expected:
- Build succeeds.
- NSIS/MSI bundle includes the WinDivert license file.

**Step 7: Commit**

```bash
git add src-tauri/vendor/windivert/LICENSE src-tauri/tauri.windows.conf.json src-tauri/build.rs README.md docs/README_EN.md docs/NetGuard_PRD_v1.0.md
git commit -m "fix: include WinDivert license in Windows distribution"
```

---

### Task 3: Make INTERCEPT Recv Errors Fail Open

**Files:**
- Modify: `src-tauri/src/capture/windivert_backend.rs:90-155`
- Test: `src-tauri/src/capture/windivert_backend.rs` existing test module

**Interface choice:**
- Option A: wrap `WinDivert` behind a testable trait and unit-test loop behavior. This gives better loop coverage but creates a new abstraction around one backend.
- Option B: keep the loop concrete, extract small pure helpers for buffer size and recv-error action, and cover the policy with unit tests.
- Pick Option B for MVP. It avoids a wrapper abstraction while still testing the safety policy.

**Step 1: Add failing tests for recv-error policy**

Add tests near the existing `windivert_backend.rs` tests:
```rust
#[test]
fn test_intercept_recv_buffer_covers_windivert_mtu_max() {
    assert!(
        INTERCEPT_RECV_BUFFER_BYTES >= 65_575,
        "INTERCEPT recv buffer must cover WINDIVERT_MTU_MAX"
    );
}

#[test]
fn test_intercept_recv_error_policy_shutdown_breaks() {
    assert_eq!(
        classify_intercept_recv_error("NoData 232"),
        InterceptRecvErrorAction::BreakCleanly
    );
}

#[test]
fn test_intercept_recv_error_policy_unknown_fails_open() {
    assert_eq!(
        classify_intercept_recv_error("ERROR_INSUFFICIENT_BUFFER 122"),
        InterceptRecvErrorAction::BreakFailOpen
    );
    assert_eq!(
        classify_intercept_recv_error("unexpected recv error"),
        InterceptRecvErrorAction::BreakFailOpen
    );
}
```

**Step 2: Run tests and verify failure**

Run:
```powershell
cd src-tauri
cargo test --lib capture::windivert_backend::tests::test_intercept_recv -- --nocapture
```

Expected:
- FAIL because helper constants/functions do not exist yet.

**Step 3: Add buffer constant and error action helper**

In `windivert_backend.rs`, add:
```rust
const INTERCEPT_RECV_BUFFER_BYTES: usize = 65_575;
const SNIFF_RECV_BUFFER_BYTES: usize = 65_575;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterceptRecvErrorAction {
    BreakCleanly,
    BreakFailOpen,
}

fn classify_intercept_recv_error(err: &str) -> InterceptRecvErrorAction {
    if err.contains("NoData") || err.contains("232") {
        InterceptRecvErrorAction::BreakCleanly
    } else {
        InterceptRecvErrorAction::BreakFailOpen
    }
}
```

Rationale:
- `65_575` matches `WINDIVERT_MTU_MAX` for WinDivert 2.2 bindings.
- In INTERCEPT mode, continuing with a live divert handle after unknown recv errors is less safe than dropping the handle and returning traffic to the OS.

**Step 4: Use the larger buffers**

Change both SNIFF and INTERCEPT buffer allocations from:
```rust
let mut buf = vec![0u8; 65535];
```
to:
```rust
let mut buf = vec![0u8; SNIFF_RECV_BUFFER_BYTES];
```
and:
```rust
let mut buf = vec![0u8; INTERCEPT_RECV_BUFFER_BYTES];
```

**Step 5: Change INTERCEPT recv error handling**

In the INTERCEPT error branch, replace the sleep-and-continue path with:
```rust
let err_str = format!("{e}");
match classify_intercept_recv_error(&err_str) {
    InterceptRecvErrorAction::BreakCleanly => {
        tracing::info!("WinDivert INTERCEPT recv got shutdown signal");
        break;
    }
    InterceptRecvErrorAction::BreakFailOpen => {
        tracing::error!("WinDivert recv error in intercept mode; dropping handle to fail open: {e}");
        break;
    }
}
```

Leave SNIFF mode tolerant of transient recv errors because SNIFF is read-only.

**Step 6: Run focused tests**

Run:
```powershell
cd src-tauri
cargo test --lib capture::windivert_backend::tests::test_intercept_recv -- --nocapture
```

Expected: PASS.

**Step 7: Run Rust capture tests**

Run:
```powershell
cd src-tauri
cargo test --lib capture -- --nocapture
```

Expected: PASS.

**Step 8: Runtime fail-open smoke test**

In elevated PowerShell with watchdog running:
```powershell
npm run tauri dev
```

Then:
1. Enable Enforce limits.
2. Generate iperf3 traffic on port 5201.
3. Disable Enforce limits.
4. Confirm normal browsing/iperf traffic resumes.

Expected:
- No persistent network freeze.
- Turning intercept off restores SNIFF mode.

**Step 9: Commit**

```bash
git add src-tauri/src/capture/windivert_backend.rs
git commit -m "fix: fail open on intercept receive errors"
```

---

### Task 4: Ensure Low Bandwidth Limits Still Pass Packet-Sized Traffic

**Files:**
- Modify: `src-tauri/src/core/rate_limiter.rs:24-76`
- Test: `src-tauri/src/core/rate_limiter.rs` existing test module

**Step 1: Add failing tests**

Add tests to `rate_limiter.rs`:
```rust
#[test]
fn test_low_rate_limit_allows_mtu_sized_packet() {
    let mgr = RateLimiterManager::new();
    mgr.set_limit(
        100,
        BandwidthLimit {
            download_bps: 500,
            upload_bps: 500,
        },
    );

    assert!(
        mgr.should_pass_packet(100, 1500, false),
        "low rate should throttle over time, not permanently block an MTU-sized packet"
    );
}

#[test]
fn test_update_rate_keeps_packet_sized_burst_floor() {
    let mgr = RateLimiterManager::new();
    mgr.set_limit(
        100,
        BandwidthLimit {
            download_bps: 10_000,
            upload_bps: 10_000,
        },
    );
    mgr.set_limit(
        100,
        BandwidthLimit {
            download_bps: 100,
            upload_bps: 100,
        },
    );

    assert!(mgr.should_pass_packet(100, 1500, false));
}
```

**Step 2: Run tests and verify failure**

Run:
```powershell
cd src-tauri
cargo test --lib core::rate_limiter::tests::test_low_rate_limit core::rate_limiter::tests::test_update_rate -- --nocapture
```

Expected:
- FAIL because `max_tokens = 2 * rate_bps` is below packet size for low rates.

**Step 3: Add packet burst floor**

In `rate_limiter.rs`, add:
```rust
const MIN_PACKET_BURST_BYTES: u64 = 65_575;

fn max_tokens_for_rate(rate_bps: u64) -> f64 {
    if rate_bps == 0 {
        0.0
    } else {
        rate_bps.saturating_mul(2).max(MIN_PACKET_BURST_BYTES) as f64
    }
}
```

**Step 4: Use the helper in bucket creation and updates**

Change `TokenBucket::new` and `TokenBucket::update_rate` to use:
```rust
let max_tokens = max_tokens_for_rate(rate_bps);
```

and:
```rust
self.max_tokens = max_tokens_for_rate(new_rate_bps);
```

**Step 5: Run focused rate limiter tests**

Run:
```powershell
cd src-tauri
cargo test --lib core::rate_limiter -- --nocapture
```

Expected: PASS.

**Step 6: Run Rust tests**

Run:
```powershell
cd src-tauri
cargo test --lib
```

Expected: PASS.

**Step 7: Runtime smoke test**

In elevated PowerShell with watchdog running:
1. Start iperf3 server: `iperf3 -s`
2. Run NetGuard.
3. Enable Enforce limits.
4. Set a low but nonzero limit, such as 1 KB/s.
5. Run iperf3 client traffic.

Expected:
- Traffic is degraded/throttled, not permanently dead.
- Removing the limit restores throughput.

**Step 8: Commit**

```bash
git add src-tauri/src/core/rate_limiter.rs
git commit -m "fix: keep token bucket burst large enough for packets"
```

---

## Phase 2: Enforcement Identity and FFI Correctness

### Task 5: Replace Port-Only Ownership with Local Endpoint Identity

**Files:**
- Modify: `src-tauri/src/core/process_mapper.rs:18-55`
- Modify: `src-tauri/src/core/win_net_table.rs:83-171`
- Modify: `src-tauri/src/capture/mod.rs:155-196`
- Modify: `src-tauri/src/capture/windivert_backend.rs:157-198`
- Test: existing modules in `process_mapper.rs`, `capture/mod.rs`, `windivert_backend.rs`

**Interface choice:**
- Option A: key by `(Family, Protocol, local_port)` only. This fixes IPv4/IPv6 collisions but still collapses different local addresses.
- Option B: key by a `LocalEndpoint` struct: address family, protocol, local address, and local port, with wildcard fallback for `0.0.0.0` / `::`.
- Pick Option B because both known callers have the local endpoint: IP Helper rows provide it, and packet parsing can extract it.

**Step 1: Add failing mapper test for address-family collision**

In `process_mapper.rs`, add:
```rust
#[test]
fn test_endpoint_lookup_distinguishes_ipv4_and_ipv6_same_port() {
    let mapper = ProcessMapper::new();
    mapper.port_map.insert(
        LocalEndpoint::ipv4(Protocol::Tcp, [127, 0, 0, 1], 443),
        10,
    );
    mapper.port_map.insert(
        LocalEndpoint::ipv6(Protocol::Tcp, [0; 16], 443),
        20,
    );

    assert_eq!(
        mapper.lookup_pid(&LocalEndpoint::ipv4(Protocol::Tcp, [127, 0, 0, 1], 443)),
        Some(10)
    );
    assert_eq!(
        mapper.lookup_pid(&LocalEndpoint::ipv6(Protocol::Tcp, [0; 16], 443)),
        Some(20)
    );
}
```

**Step 2: Run test and verify failure**

Run:
```powershell
cd src-tauri
cargo test --lib core::process_mapper::tests::test_endpoint_lookup_distinguishes -- --nocapture
```

Expected: FAIL because `LocalEndpoint` does not exist.

**Step 3: Introduce `AddressFamily` and `LocalEndpoint`**

In `process_mapper.rs`, add:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum LocalAddress {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct LocalEndpoint {
    pub proto: Protocol,
    pub address: LocalAddress,
    pub port: u16,
}
```

Add constructors for test clarity:
```rust
impl LocalEndpoint {
    pub fn ipv4(proto: Protocol, address: [u8; 4], port: u16) -> Self {
        Self { proto, address: LocalAddress::Ipv4(address), port }
    }

    pub fn ipv6(proto: Protocol, address: [u8; 16], port: u16) -> Self {
        Self { proto, address: LocalAddress::Ipv6(address), port }
    }
}
```

**Step 4: Change `port_map` and lookup**

Change:
```rust
pub(crate) port_map: DashMap<(Protocol, u16), u32>,
pub fn lookup_pid(&self, proto: Protocol, local_port: u16) -> Option<u32>
```
to:
```rust
pub(crate) port_map: DashMap<LocalEndpoint, u32>,
pub fn lookup_pid(&self, endpoint: &LocalEndpoint) -> Option<u32>
```

Add wildcard fallback:
- exact endpoint first
- IPv4 wildcard `0.0.0.0:port` second
- IPv6 wildcard `:::port` second

**Step 5: Extend packet parsing to return endpoints**

Change `parse_ip_packet` return shape from:
```rust
Option<(Protocol, u16, u16, u64)>
```
to a named struct:
```rust
pub struct ParsedPacket {
    pub proto: Protocol,
    pub src: LocalEndpoint,
    pub dst: LocalEndpoint,
    pub total_len: u64,
}
```

Populate IPv4 source/destination from bytes 12-15 and 16-19. Populate IPv6 source/destination from bytes 8-23 and 24-39.

**Step 6: Update capture call sites**

In `process_sniff_packet` and `should_pass_packet`, choose:
```rust
let local_endpoint = if outbound { parsed.src } else { parsed.dst };
```

Then call:
```rust
mapper.lookup_pid(&local_endpoint)
```

**Step 7: Update IP Helper table inserts**

In `win_net_table.rs`, insert `LocalEndpoint` keys instead of `(Protocol, port)`.

Expected mapping:
- IPv4 TCP/UDP rows use local IPv4 address fields.
- IPv6 TCP/UDP rows use local IPv6 address fields.

**Step 8: Run focused tests**

Run:
```powershell
cd src-tauri
cargo test --lib core::process_mapper capture -- --nocapture
```

Expected: PASS.

**Step 9: Run full Rust tests**

Run:
```powershell
cd src-tauri
cargo test --lib
```

Expected: PASS.

**Step 10: Commit**

```bash
git add src-tauri/src/core/process_mapper.rs src-tauri/src/core/win_net_table.rs src-tauri/src/capture/mod.rs src-tauri/src/capture/windivert_backend.rs
git commit -m "fix: map traffic by local endpoint instead of port only"
```

---

### Task 6: Make Windows IP Helper Parsing Safe and Retryable

**Files:**
- Modify: `src-tauri/src/core/win_net_table.rs:83-171`
- Test: `src-tauri/src/core/win_net_table.rs` new test module

**Step 1: Add pure row-buffer parsing helpers**

Create internal helpers for table parsing:
```rust
fn parse_table_rows<T: Copy>(buf: &[u8]) -> Vec<T> {
    // read count from first 4 bytes
    // use std::ptr::read_unaligned for each row
}
```

Do not create `&T` references from a `Vec<u8>` buffer.

**Step 2: Add failing unaligned-buffer test**

Add:
```rust
#[test]
fn test_parse_table_rows_handles_unaligned_buffer() {
    let row = MibUdpRowOwnerPid {
        local_addr: 0,
        local_port: u32::from_be(53),
        owning_pid: 123,
    };

    let mut buf = vec![0xAA];
    buf.extend_from_slice(&1u32.to_ne_bytes());
    let row_bytes = unsafe {
        std::slice::from_raw_parts(
            &row as *const MibUdpRowOwnerPid as *const u8,
            std::mem::size_of::<MibUdpRowOwnerPid>(),
        )
    };
    buf.extend_from_slice(row_bytes);

    let rows = parse_table_rows::<MibUdpRowOwnerPid>(&buf[1..]);
    assert_eq!(rows.len(), 1);
    assert_eq!(u16::from_be(rows[0].local_port as u16), 53);
    assert_eq!(rows[0].owning_pid, 123);
}
```

**Step 3: Run test and verify failure**

Run:
```powershell
cd src-tauri
cargo test --lib core::win_net_table::tests::test_parse_table_rows_handles_unaligned_buffer -- --nocapture
```

Expected: FAIL until `parse_table_rows` exists.

**Step 4: Replace unsafe reference cast**

Replace:
```rust
let row = unsafe { &*(buf.as_ptr().add(offset) as *const $row_ty) };
```
with unaligned value reads:
```rust
let row = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const $row_ty) };
```

**Step 5: Build a temporary map before swapping**

Change `refresh_port_map` so it does not clear the live map before all four table scans have completed.

Pattern:
```rust
let next_map = std::collections::HashMap::new();
// scan into next_map
port_map.clear();
for (key, pid) in next_map {
    port_map.insert(key, pid);
}
```

**Step 6: Retry `ERROR_INSUFFICIENT_BUFFER` once**

If the second IP Helper call returns `ERROR_INSUFFICIENT_BUFFER`, retry the size-query + allocation + table call once before giving up.

Expected behavior:
- transient table growth does not empty the live map
- persistent errors preserve the previous map for one scan cycle

**Step 7: Run focused tests**

Run:
```powershell
cd src-tauri
cargo test --lib core::win_net_table -- --nocapture
```

Expected: PASS.

**Step 8: Run clippy**

Run:
```powershell
cd src-tauri
cargo clippy --all-targets -- -D warnings
```

Expected: PASS.

**Step 9: Commit**

```bash
git add src-tauri/src/core/win_net_table.rs
git commit -m "fix: parse IP helper tables without aligned references"
```

---

### Task 7: Remove PID-Reuse Identity Leakage

**Files:**
- Modify: `src-tauri/src/core/process_mapper.rs:130-149`
- Modify: `src-tauri/src/core/rate_limiter.rs:195-207` if cleanup cadence changes
- Modify: `src-tauri/src/config.rs:34-36` if cleanup constant changes
- Test: `src-tauri/src/core/process_mapper.rs`

**Step 1: Add failing test for executable path refresh**

In `process_mapper.rs`, add a pure helper if needed:
```rust
fn upsert_process_info(
    process_info: &DashMap<u32, ProcessInfo>,
    pid: u32,
    name: String,
    exe_path: String,
) {
    // implementation added later
}
```

Then add:
```rust
#[test]
fn test_upsert_process_info_updates_exe_path_for_reused_pid() {
    let map = DashMap::new();
    upsert_process_info(&map, 42, "old.exe".into(), r"C:\old.exe".into());
    upsert_process_info(&map, 42, "new.exe".into(), r"C:\new.exe".into());

    let info = map.get(&42).unwrap();
    assert_eq!(info.name, "new.exe");
    assert_eq!(info.exe_path, r"C:\new.exe");
}
```

**Step 2: Run test and verify failure**

Run:
```powershell
cd src-tauri
cargo test --lib core::process_mapper::tests::test_upsert_process_info_updates_exe_path -- --nocapture
```

Expected: FAIL until helper exists/updates exe path.

**Step 3: Update process info on every scan**

In `refresh_process_info`, update both `name` and `exe_path` for existing PIDs. Do not leave `exe_path` unchanged when PID is reused.

**Step 4: Tighten stale cleanup**

Change stale cleanup to run every scan cycle, or reduce `STALE_PID_CLEANUP_INTERVAL` to `1`.

Rationale:
- PID reuse can happen before the current 5-second cleanup window.
- Running cleanup every 500ms is cheap compared with network capture risk.

**Step 5: Run focused tests**

Run:
```powershell
cd src-tauri
cargo test --lib core::process_mapper core::rate_limiter -- --nocapture
```

Expected: PASS.

**Step 6: Commit**

```bash
git add src-tauri/src/core/process_mapper.rs src-tauri/src/config.rs src-tauri/src/core/rate_limiter.rs
git commit -m "fix: refresh process identity for reused pids"
```

---

## Phase 3: UI Truthfulness and Input Safety

### Task 8: Show Pending Rules When INTERCEPT Is Inactive

**Files:**
- Modify: `src/App.tsx:62-70`
- Modify: `src/components/ProcessTable.tsx:8-173`
- Modify: `src/components/StatusBar.tsx:4-30`
- Modify: `src/components/ContextMenu.tsx:5-61`
- Test: create `src/components/StatusBar.test.tsx`
- Test: create `src/components/ProcessTable.test.tsx`

**Step 1: Add failing StatusBar test**

Create `src/components/StatusBar.test.tsx`:
```tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { StatusBar } from "./StatusBar";

describe("StatusBar", () => {
  it("labels rules as pending when intercept is inactive", () => {
    render(
      <StatusBar
        processCount={3}
        shownCount={3}
        limits={{ 100: { download_bps: 1024, upload_bps: 0 } }}
        blockedPids={new Set([200])}
        interceptActive={false}
      />
    );

    expect(screen.getByText("1 pending limit")).toBeInTheDocument();
    expect(screen.getByText("1 pending block")).toBeInTheDocument();
  });
});
```

**Step 2: Run test and verify failure**

Run:
```bash
npm test -- src/components/StatusBar.test.tsx
```

Expected: FAIL because current labels say `limited` / `blocked`.

**Step 3: Pass `interceptActive` into ProcessTable and ContextMenu**

In `App.tsx`, pass:
```tsx
interceptActive={settings.interceptActive}
```
to `ProcessTable` and `ContextMenu`.

**Step 4: Update StatusBar wording**

Expected wording:
- intercept active + limits: `N limited`
- intercept inactive + limits: `N pending limit`
- intercept active + blocks: `N blocked`
- intercept inactive + blocks: `N pending block`

**Step 5: Update ProcessTable row state**

Add `interceptActive` prop.

Expected row states:
- active + blocked: `is-blocked`
- inactive + blocked: `is-blocked-pending`
- active + limited: `is-limited`
- inactive + limited: `is-limited-pending`

Keep styling restrained. If no CSS class exists for pending state, use the same visual weight as limited but add a visible `Pending` label or tooltip near the affected control.

**Step 6: Update context menu labels**

When intercept is inactive:
- `Block` becomes `Queue Block`
- `Set Download Limit` can remain, but the menu should include a small disabled/info row: `Pending until Enforce limits is active`

**Step 7: Run frontend tests**

Run:
```bash
npm test
```

Expected: PASS.

**Step 8: Commit**

```bash
git add src/App.tsx src/components/ProcessTable.tsx src/components/StatusBar.tsx src/components/ContextMenu.tsx src/components/StatusBar.test.tsx src/components/ProcessTable.test.tsx
git commit -m "fix: show pending enforcement when intercept is inactive"
```

---

### Task 9: Distinguish Empty and Invalid Bandwidth Inputs

**Files:**
- Modify: `src/utils.ts:18-27`
- Modify: `src/utils.test.ts`
- Modify: `src/hooks/useTrafficData.ts:81-97`
- Modify: `src/components/SettingsPanel.tsx:35-40`
- Modify: `src/components/ui/LimitCell.tsx:1-49`
- Test: update existing `src/utils.test.ts`

**Interface choice:**
- Option A: keep `parseLimitInput(): number | null` and add a second validator. This preserves old callers but keeps ambiguity.
- Option B: replace it with one covering parser that returns a discriminated union.
- Pick Option B because both known callers need to distinguish empty, invalid, and numeric values.

**Step 1: Add failing parser tests**

In `src/utils.test.ts`, replace invalid-input expectations with:
```ts
expect(parseBandwidthInput("")).toEqual({ kind: "empty" });
expect(parseBandwidthInput("   ")).toEqual({ kind: "empty" });
expect(parseBandwidthInput("abc")).toEqual({ kind: "invalid" });
expect(parseBandwidthInput("12.34.56")).toEqual({ kind: "invalid" });
expect(parseBandwidthInput("500")).toEqual({ kind: "value", bps: 500 * 1024 });
```

**Step 2: Run tests and verify failure**

Run:
```bash
npm test -- src/utils.test.ts
```

Expected: FAIL because `parseBandwidthInput` does not exist.

**Step 3: Implement the discriminated parser**

In `src/utils.ts`, add:
```ts
export type BandwidthInput =
  | { kind: "empty" }
  | { kind: "invalid" }
  | { kind: "value"; bps: number };

export function parseBandwidthInput(input: string): BandwidthInput {
  const trimmed = input.trim().toLowerCase();
  if (!trimmed) return { kind: "empty" };
  const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(k|m|kb|mb)?$/);
  if (!match) return { kind: "invalid" };
  const value = parseFloat(match[1]);
  const unit = match[2] || "k";
  const bps = unit.startsWith("m")
    ? Math.round(value * 1024 * 1024)
    : Math.round(value * 1024);
  return { kind: "value", bps };
}
```

Keep `parseLimitInput` as a deprecated compatibility wrapper only if existing tests or callers still need it:
```ts
export function parseLimitInput(input: string): number | null {
  const parsed = parseBandwidthInput(input);
  return parsed.kind === "value" ? parsed.bps : null;
}
```

**Step 4: Update limit editing behavior**

In `useTrafficData.ts`:
- `empty` means clear that field.
- `invalid` means keep the existing limit and surface an error.
- `value` means apply the parsed value.

Add a state value such as:
```ts
const [limitInputError, setLimitInputError] = useState<string | null>(null);
```

Pass it to `LimitCell` for display.

**Step 5: Update alert threshold behavior**

In `SettingsPanel.tsx`:
- `empty` means threshold off.
- `invalid` means preserve old threshold and show an error.
- `value` means apply threshold.

**Step 6: Run frontend tests**

Run:
```bash
npm test
```

Expected: PASS.

**Step 7: Commit**

```bash
git add src/utils.ts src/utils.test.ts src/hooks/useTrafficData.ts src/components/SettingsPanel.tsx src/components/ui/LimitCell.tsx
git commit -m "fix: reject invalid bandwidth inputs without clearing rules"
```

---

## Phase 4: IPC, History, and Operational Hardening

### Task 10: Add Semantic Guardrails to Sensitive IPC Commands

**Files:**
- Modify: `src-tauri/src/commands/rules.rs:18-64`
- Modify: `src-tauri/src/commands/system.rs:77-104`
- Modify: `src-tauri/src/commands/logic.rs:99-156`
- Test: `src-tauri/src/commands/logic.rs` existing test module

**Step 1: Add PID validation tests**

In `commands/logic.rs`, add:
```rust
#[test]
fn test_validate_control_pid_rejects_reserved_pids() {
    assert!(validate_control_pid(0, 999).is_err());
    assert!(validate_control_pid(4, 999).is_err());
}

#[test]
fn test_validate_control_pid_rejects_current_process() {
    assert!(validate_control_pid(999, 999).is_err());
}

#[test]
fn test_validate_control_pid_accepts_user_pid() {
    assert!(validate_control_pid(1234, 999).is_ok());
}
```

**Step 2: Run tests and verify failure**

Run:
```powershell
cd src-tauri
cargo test --lib commands::logic::tests::test_validate_control_pid -- --nocapture
```

Expected: FAIL because `validate_control_pid` does not exist.

**Step 3: Implement PID validation**

Add:
```rust
pub fn validate_control_pid(pid: u32, current_pid: u32) -> Result<(), AppError> {
    if pid == 0 || pid == 4 {
        return Err(AppError::InvalidInput("Cannot control reserved system PID".into()));
    }
    if pid == current_pid {
        return Err(AppError::InvalidInput("Cannot control NetGuard's own PID".into()));
    }
    Ok(())
}
```

**Step 4: Use validation in rule commands**

In `set_bandwidth_limit`, `remove_bandwidth_limit`, `block_process`, and `unblock_process`, call:
```rust
validate_control_pid(pid, std::process::id())?;
```

Also reject unknown PIDs when the action is initiated directly from IPC:
```rust
if state.process_mapper.get_process_info(pid).is_none() {
    return Err(AppError::InvalidInput("Unknown PID".into()));
}
```

**Step 5: Restrict custom intercept filters**

Keep the UI path simple:
- `filter: None` means use the production default.
- In release builds, reject `Some(filter)` from renderer IPC.
- In debug builds, allow `Some(filter)` after validation for narrow test filters.

Expected implementation:
```rust
#[cfg(not(debug_assertions))]
if filter.is_some() {
    return Err(AppError::InvalidInput("Custom intercept filters are debug-only".into()));
}
```

**Step 6: Run Rust tests**

Run:
```powershell
cd src-tauri
cargo test --lib commands -- --nocapture
```

Expected: PASS.

**Step 7: Commit**

```bash
git add src-tauri/src/commands/rules.rs src-tauri/src/commands/system.rs src-tauri/src/commands/logic.rs
git commit -m "fix: guard sensitive network control commands"
```

---

### Task 11: Restrict Process Icon IPC to Known Processes

**Files:**
- Modify: `src-tauri/src/commands/traffic.rs:23-33`
- Modify: `src/hooks/useTrafficData.ts:61-73`
- Test: add Rust unit tests if command logic is extracted to `commands/logic.rs`

**Interface choice:**
- Option A: keep accepting `exe_path` and add path validation. This still permits arbitrary local/UNC paths.
- Option B: change `get_process_icon` to accept `pid`, then resolve the executable path from `ProcessMapper`.
- Pick Option B because the only known caller already has PID and exe_path, and backend ownership of path resolution removes arbitrary path IPC.

**Step 1: Extract command helper**

In `commands/logic.rs`, add:
```rust
pub fn validate_icon_request_pid(pid: u32) -> Result<(), AppError> {
    validate_control_pid(pid, std::process::id())
}
```

**Step 2: Change `get_process_icon` signature**

In `traffic.rs`, change:
```rust
pub fn get_process_icon(state: State<'_, AppState>, exe_path: String)
```
to:
```rust
pub fn get_process_icon(state: State<'_, AppState>, pid: u32)
```

Resolve:
```rust
let Some(info) = state.process_mapper.get_process_info(pid) else {
    return Ok(None);
};
```

Reject:
- empty path
- NUL byte
- UNC paths beginning with `\\`

**Step 3: Update frontend caller**

In `useTrafficData.ts`, change:
```ts
invoke<string | null>("get_process_icon", { exePath: path })
```
to:
```ts
invoke<string | null>("get_process_icon", { pid: p.pid })
```

Keep frontend cache keyed by `exe_path` so processes sharing an executable reuse icons.

**Step 4: Run frontend tests**

Run:
```bash
npm test
```

Expected: PASS.

**Step 5: Run Rust tests**

Run:
```powershell
cd src-tauri
cargo test --lib commands -- --nocapture
```

Expected: PASS.

**Step 6: Commit**

```bash
git add src-tauri/src/commands/traffic.rs src-tauri/src/commands/logic.rs src/hooks/useTrafficData.ts
git commit -m "fix: resolve process icons from known pids"
```

---

### Task 12: Quote Autostart Run Command

**Files:**
- Modify: `src-tauri/src/commands/system.rs:36-60`
- Test: extract pure helper into `src-tauri/src/commands/logic.rs`

**Step 1: Add failing helper test**

In `commands/logic.rs`, add:
```rust
#[test]
fn test_format_run_value_quotes_paths_with_spaces() {
    assert_eq!(
        format_run_value(r"C:\Program Files\NetGuard\netguard.exe"),
        r#""C:\Program Files\NetGuard\netguard.exe""#
    );
}
```

**Step 2: Run test and verify failure**

Run:
```powershell
cd src-tauri
cargo test --lib commands::logic::tests::test_format_run_value_quotes_paths_with_spaces -- --nocapture
```

Expected: FAIL because helper does not exist.

**Step 3: Implement helper**

Add:
```rust
pub fn format_run_value(exe_path: &str) -> String {
    format!("\"{}\"", exe_path.replace('"', "\\\""))
}
```

**Step 4: Use helper in `set_autostart`**

In `system.rs`, use:
```rust
let run_value = format_run_value(&exe_str);
```

Pass `&run_value` to `reg add`.

**Step 5: Run command tests**

Run:
```powershell
cd src-tauri
cargo test --lib commands -- --nocapture
```

Expected: PASS.

**Step 6: Commit**

```bash
git add src-tauri/src/commands/system.rs src-tauri/src/commands/logic.rs
git commit -m "fix: quote autostart registry command"
```

---

### Task 13: Bound Traffic History Queries

**Files:**
- Modify: `src-tauri/src/db/history.rs:41-84`
- Modify: `src-tauri/src/commands/traffic.rs:35-48`
- Modify: `src/hooks/useChartData.ts:12-21`
- Test: `src-tauri/src/db/history.rs` existing test module

**Interface choice:**
- Option A: add a hard SQL `LIMIT`. This caps memory but can silently truncate charts.
- Option B: add server-side aggregation to at most `max_points` rows. This keeps memory bounded and preserves the whole time range.
- Pick Option B for chart/history reads. It is slightly more implementation work but simpler and safer for callers.

**Step 1: Add failing DB aggregation test**

In `history.rs`, add:
```rust
#[test]
fn test_query_history_aggregates_to_max_points() {
    let db = open_memory_db();
    let records: Vec<_> = (0..100)
        .map(|i| make_record(1000 + i, 1, "chrome.exe", r"C:\chrome.exe", i as u64, i as u64))
        .collect();
    db.insert_traffic_batch(&records).unwrap();

    let results = db.query_history_aggregated(1000, 1099, None, 10).unwrap();
    assert!(results.len() <= 10);
    assert_eq!(results.first().unwrap().timestamp, 1000);
}
```

**Step 2: Run test and verify failure**

Run:
```powershell
cd src-tauri
cargo test --lib db::history::tests::test_query_history_aggregates_to_max_points -- --nocapture
```

Expected: FAIL because `query_history_aggregated` does not exist.

**Step 3: Implement bounded aggregation**

Add `query_history_aggregated` to `Database`:
- input: `from_timestamp`, `to_timestamp`, `process_name`, `max_points`
- compute bucket width: `((to - from) / max_points).max(1)`
- group by integer bucket
- return sums or averages consistently:
  - `bytes_sent`, `bytes_recv`: use max or final cumulative value per bucket
  - `upload_speed`, `download_speed`: use average speed per bucket

Document the aggregation contract in the function docstring.

**Step 4: Wire command**

Change `get_traffic_history` to accept:
```rust
max_points: Option<usize>
```

Use a safe default, e.g. `2_000`, and a hard cap, e.g. `10_000`.

**Step 5: Update frontend**

In `useChartData.ts`, pass:
```ts
maxPoints: 2000
```

**Step 6: Run DB tests**

Run:
```powershell
cd src-tauri
cargo test --lib db::history -- --nocapture
```

Expected: PASS.

**Step 7: Run frontend tests**

Run:
```bash
npm test
```

Expected: PASS.

**Step 8: Commit**

```bash
git add src-tauri/src/db/history.rs src-tauri/src/commands/traffic.rs src/hooks/useChartData.ts
git commit -m "fix: bound traffic history query size"
```

---

## Phase 5: Tooling, Tests, and Documentation Hygiene

### Task 14: Remove Unused Opener Plugin and Capability

**Files:**
- Modify: `package.json:16`
- Modify: `package-lock.json`
- Modify: `src-tauri/Cargo.toml:18`
- Modify: `src-tauri/Cargo.lock`
- Modify: `src-tauri/src/lib.rs:40-42`
- Modify: `src-tauri/capabilities/default.json:6-10`

**Step 1: Remove frontend dependency**

Run:
```bash
npm uninstall @tauri-apps/plugin-opener
```

**Step 2: Remove Rust dependency**

In `src-tauri/Cargo.toml`, remove:
```toml
tauri-plugin-opener = "2"
```

**Step 3: Remove plugin initialization**

In `src-tauri/src/lib.rs`, remove:
```rust
.plugin(tauri_plugin_opener::init())
```

**Step 4: Remove capability permission**

In `src-tauri/capabilities/default.json`, remove:
```json
"opener:default",
```

**Step 5: Update lockfile**

Run:
```powershell
cd src-tauri
cargo update -p tauri-plugin-opener --precise 0.0.0
```

If the command is not appropriate because the dependency is removed, run:
```powershell
cd src-tauri
cargo check
```
and let Cargo update `Cargo.lock`.

**Step 6: Verify no opener references remain**

Run:
```bash
rg -n "plugin-opener|tauri_plugin_opener|opener:" package.json package-lock.json src-tauri src
```

Expected: no matches.

**Step 7: Run tests**

Run:
```bash
npm test
```

Run:
```powershell
cd src-tauri
cargo test --lib
```

Expected: PASS.

**Step 8: Commit**

```bash
git add package.json package-lock.json src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/lib.rs src-tauri/capabilities/default.json
git commit -m "chore: remove unused opener capability"
```

---

### Task 15: Pin CI Permissions and Tool Versions

**Files:**
- Modify: `.github/workflows/ci.yml:10-133`

**Step 1: Restrict default permissions**

Change workflow-level permissions to:
```yaml
permissions:
  contents: read
```

Add release-job override:
```yaml
permissions:
  contents: write
```

only under the `release` job.

**Step 2: Pin cargo-audit version**

Replace:
```yaml
run: cargo install cargo-audit --locked
```
with a pinned version:
```yaml
run: cargo install cargo-audit --version 0.21.2 --locked
```

Use the latest known-good version at implementation time if `0.21.2` is stale, but keep it explicit.

**Step 3: Pin action refs where feasible**

For third-party actions:
- keep first-party `actions/*@v4` if the team accepts tag pins
- replace non-first-party mutable refs with explicit version tags or SHAs

Minimum change:
```yaml
uses: dtolnay/rust-toolchain@stable
```
should be replaced with a pinned Rust toolchain action ref or a `rustup toolchain install stable` shell step.

**Step 4: Validate workflow syntax**

Run:
```bash
rg -n "contents: write|cargo install cargo-audit|@stable" .github/workflows/ci.yml
```

Expected:
- `contents: write` appears only in the release job.
- `cargo-audit` has an explicit version.
- No `dtolnay/rust-toolchain@stable` remains unless intentionally accepted and documented.

**Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: reduce permissions and pin audit tooling"
```

---

### Task 16: Fix Node Version and Test Count Documentation

**Files:**
- Modify: `README.md:27-48`
- Modify: `docs/README_EN.md:25-46`
- Modify: `CLAUDE.md:9`
- Modify: `docs/NetGuard_PRD_v1.0.md` if it repeats stale counts or Node requirements

**Step 1: Update Node requirement**

Change Node docs from:
```text
Node.js 18+
```
to:
```text
Node.js 20.19+ or 22.12+
```

Rationale:
- `vite`, `jsdom`, and related locked dependencies require Node 20.19+ or 22.12+.
- CI already uses Node 20.

**Step 2: Update Rust test count**

Change Rust test count from `114` to the current count only after verifying on Windows:
```powershell
cd src-tauri
cargo test --lib
```

If the final Windows count differs from the static attribute count, document the runtime count, not the macOS static count.

**Step 3: Verify text references**

Run:
```bash
rg -n "Node.js 18|114|60 frontend|Rust.*test" README.md docs CLAUDE.md
```

Expected:
- No stale Node 18 requirement.
- Test counts match verified results.

**Step 4: Commit**

```bash
git add README.md docs/README_EN.md CLAUDE.md docs/NetGuard_PRD_v1.0.md
git commit -m "docs: update runtime requirements and test counts"
```

---

### Task 17: Clean Up Frontend Async Test Warnings

**Files:**
- Modify: `src/hooks/useSettings.test.ts`

**Step 1: Reproduce warning**

Run:
```bash
npm test -- src/hooks/useSettings.test.ts
```

Expected:
- Tests pass but emit React `act(...)` warnings.

**Step 2: Wrap async state updates**

Use `waitFor` or `act` from `@testing-library/react` so tests wait for mount-time invokes:
```ts
await waitFor(() => {
  expect(result.current.notifThreshold).toBe(1024);
});
```

For tests that only verify initial defaults, either mock unresolved promises or wait for all mount promises to settle before finishing the test.

**Step 3: Verify warning-free focused test**

Run:
```bash
npm test -- src/hooks/useSettings.test.ts
```

Expected:
- PASS.
- No `act(...)` warning.

**Step 4: Verify full frontend suite**

Run:
```bash
npm test
```

Expected:
- 60+ tests pass.
- No React `act(...)` warnings.

**Step 5: Commit**

```bash
git add src/hooks/useSettings.test.ts
git commit -m "test: await settings hook async updates"
```

---

### Task 18: Add High-Risk FFI Test Coverage

**Files:**
- Modify: `src-tauri/src/core/win_net_table.rs`
- Modify: `src-tauri/src/core/icon_extractor.rs`

**Step 1: Add win_net_table parser tests**

Cover:
- empty buffer
- declared row count larger than buffer capacity
- unaligned row buffer
- IPv4 local-port byte order
- IPv6 local-port byte order

**Step 2: Extract icon BMP validation helpers if needed**

Keep `extract_icon` as the only FFI-heavy function. Add pure tests for:
- BMP header dimensions
- pixel data size
- invalid dimension rejection helper if extracted

Do not attempt to unit-test `ExtractIconExW` on non-Windows.

**Step 3: Run focused tests**

Run:
```powershell
cd src-tauri
cargo test --lib core::win_net_table core::icon_extractor -- --nocapture
```

Expected: PASS.

**Step 4: Commit**

```bash
git add src-tauri/src/core/win_net_table.rs src-tauri/src/core/icon_extractor.rs
git commit -m "test: cover Windows FFI parsing helpers"
```

---

## Final Verification Checklist

Run on Windows 11 in an elevated terminal unless noted otherwise.

**Rust/backend:**
```powershell
cd src-tauri
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --lib
```

**Frontend:**
```bash
npm test
npm run build
```

**Tauri build:**
```powershell
npm run tauri build
```

**Recovery scripts:**
```powershell
rg -n "WinDivert14" scripts docs CLAUDE.md
sc.exe query WinDivert
```

**WinDivert runtime smoke test:**
1. Start watchdog in separate elevated PowerShell:
   ```powershell
   .\scripts\watchdog.ps1 -TimeoutSeconds 10
   ```
2. Start iperf3 server:
   ```powershell
   iperf3 -s
   ```
3. Run app:
   ```powershell
   npm run tauri dev
   ```
4. Enable Enforce limits.
5. Apply a low limit to the iperf3 client process.
6. Confirm traffic is throttled, not permanently blocked.
7. Disable Enforce limits.
8. Confirm normal traffic resumes.
9. Run emergency recovery script and confirm it targets `WinDivert`.

**Git hygiene:**
```bash
git status --short
git log --oneline -n 20
```

Expected:
- No unrelated files staged.
- Each task has one small logical commit.

