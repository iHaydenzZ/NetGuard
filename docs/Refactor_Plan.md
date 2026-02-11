# NetGuard 代码库可维护性提升计划

> **目标：** 提升代码库的模块化程度、类型安全性和可测试性，使 AI Agent 和人类开发者都能更高效地维护和扩展项目。
>
> **原则：** 每批改动完成后，项目处于可编译、43 Rust + 31 前端测试全过、可正常运行的稳定状态。遵循 CLAUDE.md 中 "Make it work → Make it right → Make it fast" 的渐进策略。

---

## 第一批：基础设施层（低风险，纯增量添加）

本批不修改任何现有逻辑，仅新增基础设施代码。所有现有测试应无需修改即可通过。

### 1.1 统一错误类型

**现状：** `commands.rs` 中 22 个 command 函数的错误处理不一致——部分返回 `Result<_, String>`（通过 `.map_err(|e| e.to_string())`），部分不返回错误（`set_bandwidth_limit`、`block_process` 等直接忽略潜在失败）。前端无法区分错误类型。

**改动：** 新建 `src-tauri/src/error.rs`，定义 `AppError` 枚举，实现 `Into<tauri::InvokeError>` 或 `Serialize`，统一所有 command 的返回类型。

| AC ID | 验收标准 | 验证方法 |
|-------|---------|---------|
| AC-R1.1 | 存在 `src-tauri/src/error.rs`，定义 `AppError` 枚举，至少覆盖 `Database`、`Capture`、`RateLimiter`、`Io`、`InvalidInput` 五类错误 | 代码审查 |
| AC-R1.2 | `AppError` 实现 `Serialize` 和 `Display`，可直接作为 Tauri command 的 `Err` 返回前端 | `cargo check` 通过 |
| AC-R1.3 | 所有 22 个 `#[tauri::command]` 函数统一返回 `Result<T, AppError>`，不再出现 `Result<_, String>` 或无错误返回 | `grep "Result<" commands.rs` 验证无 `String` 错误类型 |
| AC-R1.4 | 前端 `App.tsx` 中的 `invoke` 调用能捕获结构化错误对象（含 `kind` 和 `message` 字段），而非纯字符串 | 手动触发一个错误场景（如对不存在的 profile 调用 apply），检查前端收到的错误格式 |
| AC-R1.5 | 全部 43 项 Rust 测试和 31 项前端测试通过，无回归 | `cargo test --lib` + `npm test` |

### 1.2 集中配置常量

**现状：** 硬编码数值散布在 `lib.rs` 的多个线程启动位置——history recorder 5 秒、tray updater 2 秒、persistent-rules 3 秒、pruning 90 天 / 17280 次计数、`remove_stale` 10 秒、Top 5 消费者等。修改需要在整个文件中搜索。

**改动：** 新建 `src-tauri/src/config.rs`，将所有运行时常量集中为 `pub const`，在 `lib.rs` 中引用。

| AC ID | 验收标准 | 验证方法 |
|-------|---------|---------|
| AC-R2.1 | 存在 `src-tauri/src/config.rs`，导出所有运行时常量，每个常量有文档注释说明用途和单位 | 代码审查 |
| AC-R2.2 | 至少包含以下常量：`STATS_INTERVAL_SECS`、`HISTORY_RECORD_INTERVAL_SECS`、`TRAY_UPDATE_INTERVAL_SECS`、`PERSISTENT_RULES_INTERVAL_SECS`、`PRUNE_MAX_AGE_DAYS`、`PRUNE_CHECK_INTERVAL_TICKS`、`STALE_PROCESS_TIMEOUT_SECS`、`TRAY_TOP_CONSUMERS_COUNT` | `config.rs` 中存在对应常量 |
| AC-R2.3 | `lib.rs` 中不再出现任何硬编码的时间间隔或计数数字，全部引用 `config::` 常量 | `grep` 搜索 `lib.rs` 中 `from_secs(` 和 `from_millis(` 后的数字字面量，应全部替换为常量引用 |
| AC-R2.4 | 全部测试通过，运行时行为不变 | `cargo test --lib` + 手动运行验证托盘更新频率、历史记录频率不变 |

### 1.3 前后端类型共享

**现状：** 前端 `App.tsx` 顶部手写了 `ProcessTraffic`、`BandwidthLimit`、`TrafficRecord`、`TrafficSummary` 等 TypeScript interface，与 Rust 端的 struct 靠人工保持一致。字段重命名或新增时无编译期检查。

**改动：** 引入 `specta` 或 `ts-rs` crate，从 Rust struct 自动生成 TypeScript 类型定义文件。

| AC ID | 验收标准 | 验证方法 |
|-------|---------|---------|
| AC-R3.1 | `Cargo.toml` 中添加类型导出依赖（`specta` 或 `ts-rs`），所有 IPC 相关的 Rust struct 添加对应的 derive 宏 | 代码审查 |
| AC-R3.2 | 存在自动生成的 `src/bindings.ts`（或等效文件），包含所有 IPC 类型定义 | 文件存在且内容与 Rust struct 一致 |
| AC-R3.3 | `App.tsx` 顶部不再手写 interface 定义，改为从 `bindings.ts` 导入 | `App.tsx` 中 `import { ProcessTraffic, ... } from "./bindings"` |
| AC-R3.4 | 在 Rust 端新增一个字段后，`cargo test` 或 `npm run build` 会产生编译错误或类型不匹配告警 | 手动测试：在 `ProcessTrafficSnapshot` 中加一个临时字段，验证前端 TypeScript 报错 |
| AC-R3.5 | CI 流水线中添加类型生成步骤，确保生成的类型文件与 Rust 代码同步 | `.github/workflows/ci.yml` 中包含类型检查步骤 |
| AC-R3.6 | 全部测试通过，运行时行为不变 | `cargo test --lib` + `npm test` + `npm run build` |

### 第一批完成标志

- [ ] `error.rs`、`config.rs`、`bindings.ts` 三个新文件存在且被使用
- [ ] `cargo test --lib` 通过 43 项测试
- [ ] `npm test` 通过 31 项测试
- [ ] `npm run tauri build` 成功产出安装包
- [ ] 手动运行 SNIFF 模式正常监控，无功能回归

---

## 第二批：逻辑重构（中等风险，移动代码 + 补测试）

本批涉及代码移动和逻辑提取，但不改变业务行为。每个子任务完成后需跑全量测试。

### 2.1 提取 command 业务逻辑为可测试纯函数

**现状：** `commands.rs` 中 `save_profile` 和 `apply_profile` 包含较重的业务逻辑（遍历快照匹配进程、批量应用规则），但由于直接依赖 `State<AppState>`，无法在不启动 Tauri 的情况下单元测试。

**改动：** 将核心业务逻辑提取到独立的纯函数（接收普通参数而非 Tauri State），command 函数变为薄委托层。新函数添加单元测试。

| AC ID | 验收标准 | 验证方法 |
|-------|---------|---------|
| AC-R4.1 | `save_profile` 的核心逻辑被提取为纯函数（如 `build_profile_rules(limits, blocked_pids, snapshot) -> Vec<RuleEntry>`），不依赖 `State` 或 `AppState` | 代码审查：函数签名不含 `State<>` |
| AC-R4.2 | `apply_profile` 的规则匹配逻辑被提取为纯函数（如 `match_rules_to_processes(rules, snapshot) -> Vec<ApplyAction>`），不依赖 `State` | 代码审查 |
| AC-R4.3 | `enable_intercept_mode` 和 `disable_intercept_mode` 中的引擎切换逻辑被提取为独立函数 | 代码审查 |
| AC-R4.4 | 为每个提取的纯函数添加至少 3 个单元测试，覆盖：正常路径、空输入、边界情况（如 rules 中的 exe_path 不匹配任何进程） | `cargo test` 新增测试全部通过 |
| AC-R4.5 | `commands.rs` 中的 command 函数体均不超过 15 行（不含注释），仅做参数解包、委托调用、结果转换 | 代码审查 |
| AC-R4.6 | Rust 测试总数从 43 项增加到至少 55 项 | `cargo test --lib` 输出 |
| AC-R4.7 | 全部现有测试 + 新增测试通过，运行时行为不变 | `cargo test --lib` + `npm test` |

### 2.2 后台线程生命周期管理

**现状：** `lib.rs` 的 `.setup()` 闭包中手动启动 4 个 `std::thread`（process scanner、stats aggregator、history recorder、tray updater）加 1 个 persistent-rules 线程。线程之间有隐含的时序依赖（如 history recorder 依赖 traffic tracker snapshot 的质量，而这依赖 process mapper 已启动扫描），但这些依赖仅靠代码顺序保证。线程的 `JoinHandle` 未保存，无法优雅关闭。

**改动：** 新建 `src-tauri/src/services.rs`，定义 `BackgroundServices` 结构体统一管理所有后台线程的启动和关闭。

| AC ID | 验收标准 | 验证方法 |
|-------|---------|---------|
| AC-R5.1 | 存在 `src-tauri/src/services.rs`，定义 `BackgroundServices` 结构体 | 代码审查 |
| AC-R5.2 | `BackgroundServices::start()` 按照正确的依赖顺序启动所有后台线程：process scanner → stats aggregator → history recorder → tray updater → persistent-rules | 代码审查：启动顺序明确 |
| AC-R5.3 | 所有线程的 `JoinHandle` 保存在 `BackgroundServices` 中，通过共享的 `AtomicBool` 支持优雅关闭 | 代码审查 |
| AC-R5.4 | `lib.rs` 的 `.setup()` 闭包简化为：创建 AppState → 创建 BackgroundServices → 启动。不再包含线程启动细节 | `lib.rs` setup 闭包不超过 40 行 |
| AC-R5.5 | `lib.rs` 中除 `run()` 外不再有其他独立函数（`update_tray_and_notify`、`apply_persistent_rules`、`build_tray_menu`、`format_speed_compact` 均移至 `services.rs` 或更合适的模块） | `grep "^fn " lib.rs` 仅显示 `run()` |
| AC-R5.6 | 全部测试通过，运行时行为不变 | `cargo test --lib` + `npm test` + 手动运行验证托盘更新和持久化规则正常 |

### 2.3 分离 Win32 FFI 与图标提取

**现状：** `core/process_mapper.rs` 将三种不同职责混在一起：进程信息查询（sysinfo）、Windows TCP/UDP 表 FFI（iphlpapi）、Shell32/GDI 图标提取（ExtractIconExW + GetDIBits + 手动 BMP 构建）。图标提取代码包含大量底层像素操作，与进程映射的核心逻辑无关。

**改动：** 将 Win32 FFI 和图标提取代码拆分到独立模块。

| AC ID | 验收标准 | 验证方法 |
|-------|---------|---------|
| AC-R6.1 | `win_icon_api` FFI 模块和图标提取逻辑（`get_icon_base64` 及其所有辅助函数、BMP 构建代码）移至 `core/icon_extractor.rs` | 代码审查 |
| AC-R6.2 | `iphlpapi` 相关的 FFI 定义（TCP/UDP 表结构体和 extern 函数）移至 `core/win_net_table.rs`（或 `core/platform/` 子目录） | 代码审查 |
| AC-R6.3 | `process_mapper.rs` 仅保留：`ProcessMapper` 结构体、`get_process_info()`、`start_scanning()`、`connection_counts()`，以及对 icon_extractor 和 win_net_table 的调用 | `process_mapper.rs` 行数减少至少 50% |
| AC-R6.4 | 所有 `#[cfg(target_os = "windows")]` 标注正确，非 Windows 平台编译不受影响 | `cargo check`（如有条件可交叉检查） |
| AC-R6.5 | 全部测试通过 | `cargo test --lib` |

### 第二批完成标志

- [ ] 纯函数提取完毕，Rust 测试数 ≥ 55
- [ ] `BackgroundServices` 统一管理后台线程
- [ ] `process_mapper.rs` 行数减少 ≥ 50%
- [ ] `lib.rs` setup 闭包 ≤ 40 行，无独立辅助函数
- [ ] `cargo test --lib` + `npm test` + `npm run tauri build` 全部通过

---

## 第三批：结构重组（较高风险，大范围文件移动）

本批涉及文件拆分和大量 import 路径变更，git diff 最大。建议一个子任务一个 PR，每次合并前跑全量测试。

### 3.1 拆分 commands.rs

**现状：** 22 个 command 函数 + `AppState` 定义在单个文件中，跨越 7 个功能域。AI Agent 修改一个领域时必须加载全部内容。

**改动：** 拆分为 `commands/` 目录结构。

| AC ID | 验收标准 | 验证方法 |
|-------|---------|---------|
| AC-R7.1 | `commands.rs` 重构为 `commands/` 目录，包含 `mod.rs` + 按领域拆分的子模块 | 目录结构审查 |
| AC-R7.2 | 拆分方案为：`state.rs`（AppState 定义）、`traffic.rs`（F1 流量查询 + F4 历史 + 图标）、`rules.rs`（F2 限速 + F3 防火墙 + F5 配置方案）、`system.rs`（F6 通知阈值 + F7 自动启动 + 拦截模式切换） | 文件存在且内容对应 |
| AC-R7.3 | `commands/mod.rs` 使用 `pub use` 重新导出所有 command 函数，确保 `lib.rs` 中的 `generate_handler![]` 宏不需要修改 | `lib.rs` 中 `commands::` 引用无变化 |
| AC-R7.4 | 每个子模块的代码行数不超过 120 行（不含测试） | `wc -l` 验证 |
| AC-R7.5 | 全部测试通过 | `cargo test --lib` + `npm test` |

### 3.2 拆分 db/mod.rs

**现状：** `db/mod.rs` 包含两张表（`traffic_history` 和 `bandwidth_rules`）的全部 CRUD 方法、schema 定义、辅助函数和所有单元测试。两张表的逻辑完全独立。

**改动：** 按表/领域拆分。

| AC ID | 验收标准 | 验证方法 |
|-------|---------|---------|
| AC-R8.1 | `db/` 目录包含：`mod.rs`（Database struct + open/migrate + 公共类型 re-export）、`history.rs`（traffic_history 表的 insert/query/prune/top_consumers）、`rules.rs`（bandwidth_rules 表的 save/load/list/delete profile） | 文件存在且内容对应 |
| AC-R8.2 | `Database` struct 和 `open()` 方法保留在 `mod.rs`，子模块通过 `impl Database` 扩展方法 | 代码审查 |
| AC-R8.3 | 所有现有 db 单元测试保持在各自的子模块中，且全部通过 | `cargo test --lib` |
| AC-R8.4 | `commands/` 中对 `db::` 的 import 路径无需变化（通过 `mod.rs` re-export） | `cargo check` |

### 3.3 拆分前端 App.tsx

**现状：** 整个前端 UI 在一个 `App.tsx` 文件中，包含约 20 个 `useState`、6+ 个 `useEffect`、全部事件处理函数和 JSX 渲染。典型的 "God Component"。

**改动：** 按 UI 区域拆分为组件和自定义 hooks。

| AC ID | 验收标准 | 验证方法 |
|-------|---------|---------|
| AC-R9.1 | 新建 `src/components/` 目录，至少包含以下组件文件：`ProcessTable.tsx`（进程表格 + 排序 + 过滤 + 行内编辑）、`HistoryChart.tsx`（历史图表 + 时间范围选择 + Top 消费者）、`LiveSpeedChart.tsx`（60 秒实时速度曲线）、`SettingsPanel.tsx`（设置面板 + 拦截模式开关 + 自动启动 + 通知阈值）、`ProfileBar.tsx`（配置方案栏 + 新增/切换/删除）、`ContextMenu.tsx`（右键菜单） | 文件存在 |
| AC-R9.2 | 新建 `src/hooks/` 目录，至少包含：`useTrafficData.ts`（流量数据订阅 + 限速/阻断状态管理）、`useProfiles.ts`（配置方案 CRUD）、`useSettings.ts`（通知阈值 + 自动启动 + 拦截模式状态） | 文件存在 |
| AC-R9.3 | `App.tsx` 简化为组合根组件，仅负责布局和子组件组装，行数不超过 100 行 | `wc -l App.tsx` |
| AC-R9.4 | 所有类型定义从 `bindings.ts` 导入，组件内不出现手写的 interface 定义（除组件自身的 Props 类型） | `grep "interface" src/components/*.tsx` 仅显示 Props 定义 |
| AC-R9.5 | 小型通用组件（`Toggle`、`Badge`、`CtxItem`、`Th`、`LimitCell`、`SettingToggle`）移至 `src/components/ui/` 目录 | 文件存在 |
| AC-R9.6 | 全部 31 项前端测试通过。如现有测试因 import 路径变更需修改，修改后通过 | `npm test` |
| AC-R9.7 | `npm run tauri dev` 启动后 UI 表现与重构前完全一致 | 手动对比测试 |

### 3.4 公开接口文档化

**现状：** 模块的 `pub` 导出列表未被系统化管理，外部消费者（包括 AI Agent）需要读完整个实现才能理解模块职责边界。

**改动：** 每个模块的 `mod.rs` 明确管理 `pub use` 导出，添加模块级文档注释。

| AC ID | 验收标准 | 验证方法 |
|-------|---------|---------|
| AC-R10.1 | 每个模块的 `mod.rs`（`capture/`、`core/`、`db/`、`commands/`）顶部有 `//!` 模块级文档注释，描述职责边界和公开接口 | 代码审查 |
| AC-R10.2 | 每个模块的 `mod.rs` 使用显式的 `pub use` 重新导出公开类型和函数，而非依赖子模块的 `pub` 可见性透传 | 代码审查 |
| AC-R10.3 | `CLAUDE.md` 中的项目结构树更新，反映重构后的实际文件布局 | `CLAUDE.md` 中的目录树与实际 `find` 结果一致 |
| AC-R10.4 | `cargo doc --no-deps` 生成的文档中，每个公开类型和函数都有文档注释 | `cargo doc` 无 `missing_docs` 警告（可选：启用 `#![warn(missing_docs)]`） |

### 第三批完成标志

- [ ] `commands/` 目录拆分完成，每个子模块 ≤ 120 行
- [ ] `db/` 目录拆分完成
- [ ] 前端 `App.tsx` ≤ 100 行，组件和 hooks 各就各位
- [ ] 所有模块有文档注释和显式 `pub use`
- [ ] `CLAUDE.md` 项目结构树与实际一致
- [ ] `cargo test --lib`（≥ 55 项）+ `npm test`（31 项）+ `npm run tauri build` 全部通过
- [ ] 手动运行验证全部功能（SNIFF 监控、限速编辑、防火墙开关、历史图表、配置方案、系统托盘、通知阈值）无回归

---

## 重构后目标架构

```
src-tauri/src/
├── main.rs                        # 入口 → netguard_lib::run()
├── lib.rs                         # Tauri Builder + setup（≤ 40 行闭包）
├── error.rs                       # AppError 统一错误类型
├── config.rs                      # 运行时常量集中管理
├── services.rs                    # BackgroundServices 后台线程生命周期
├── commands/
│   ├── mod.rs                     # pub use 重导出所有 command
│   ├── state.rs                   # AppState 定义
│   ├── traffic.rs                 # F1 流量查询 + F4 历史 + 图标
│   ├── rules.rs                   # F2 限速 + F3 防火墙 + F5 配置方案
│   └── system.rs                  # F6 通知 + F7 自启 + 拦截模式
├── capture/
│   ├── mod.rs                     # CaptureEngine
│   └── windivert_backend.rs       # WinDivert SNIFF + INTERCEPT
├── core/
│   ├── mod.rs                     # pub use 重导出
│   ├── traffic.rs                 # TrafficTracker + DashMap 统计
│   ├── rate_limiter.rs            # 令牌桶限速器
│   ├── process_mapper.rs          # PID ↔ 端口映射（精简）
│   ├── icon_extractor.rs          # Win32 图标提取 + BMP 构建
│   └── win_net_table.rs           # iphlpapi FFI（TCP/UDP 表）
└── db/
    ├── mod.rs                     # Database struct + 连接管理 + 迁移
    ├── history.rs                 # traffic_history 表 CRUD
    └── rules.rs                   # bandwidth_rules 表 CRUD

src/
├── main.tsx                       # React 入口
├── App.tsx                        # 组合根组件（≤ 100 行）
├── bindings.ts                    # 自动生成的 TypeScript 类型
├── utils.ts                       # 通用工具函数
├── utils.test.ts                  # 工具函数测试
├── styles.css                     # Tailwind 入口
├── components/
│   ├── ProcessTable.tsx           # 进程表格
│   ├── HistoryChart.tsx           # 历史图表
│   ├── LiveSpeedChart.tsx         # 实时速度曲线
│   ├── SettingsPanel.tsx          # 设置面板
│   ├── ProfileBar.tsx             # 配置方案栏
│   ├── ContextMenu.tsx            # 右键菜单
│   └── ui/                        # 通用 UI 原子组件
│       ├── Toggle.tsx
│       ├── Badge.tsx
│       ├── Th.tsx
│       ├── LimitCell.tsx
│       └── CtxItem.tsx
└── hooks/
    ├── useTrafficData.ts          # 流量数据 + 限速/阻断状态
    ├── useProfiles.ts             # 配置方案 CRUD
    └── useSettings.ts             # 通知 + 自启 + 拦截模式
```

---

## 风险控制

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| 拦截模式 bug 导致网络冻结 | 高 | 重构期间仅在 SNIFF 模式下测试；拦截模式相关代码移动后使用 watchdog 脚本验证 |
| 大规模文件移动导致 merge conflict | 中 | 第三批每个子任务单独 PR；不与功能开发并行 |
| 类型生成工具（specta/ts-rs）与 Tauri v2 兼容性 | 中 | 第一批优先验证工具链兼容性；如不兼容退回手动同步 + lint 规则 |
| 前端组件拆分后状态提升不当导致性能问题 | 低 | 使用 React DevTools Profiler 对比重构前后渲染次数 |