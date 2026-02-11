# NetGuard

Windows 桌面应用，用于监控每个进程的网络流量并控制带宽。

[English](docs/README_EN.md)

## 功能特性

- **实时进程监控** — 实时展示所有活跃网络连接的进程，显示进程图标、上传/下载速度、累计流量和连接数。支持列排序、搜索过滤，每秒刷新。
- **按进程限速** — 为任意进程单独设置上传/下载速度上限，支持行内编辑和右键菜单。基于令牌桶算法，允许 2 倍突发流量。
- **按进程防火墙** — 一键切换开关，阻止/放行单个应用的网络访问。被阻止的数据包将被静默丢弃。
- **流量历史与分析** — SQLite 存储的时序图表（1 小时/24 小时/7 天/30 天），展示每个进程的带宽趋势和流量排行。自动清理 90 天前的数据。
- **规则配置** — 保存并切换多组命名的带宽规则（如"游戏模式"、"视频会议模式"），重启后自动恢复。
- **系统托盘** — 后台监控，悬浮显示总速度，托盘菜单展示 Top 5 进程，支持带宽阈值通知。
- **开机自启与规则持久化** — 登录时自动启动，按可执行文件路径自动匹配并重新应用规则。
- **实时速度图表** — 点击任意进程查看 60 秒实时速度曲线。

## 技术栈

| 层级 | 技术 |
|------|------|
| 后端 | Rust, Tokio, DashMap |
| 框架 | Tauri v2 |
| 前端 | React, TypeScript, Tailwind CSS, Recharts |
| 抓包 | WinDivert 2.x（SNIFF + INTERCEPT 模式） |
| 数据库 | SQLite（rusqlite, WAL 模式） |
| 测试 | cargo test（43 项）, Vitest（31 项） |

## 环境要求

- **Windows 11** 22H2+
- **Rust** 1.75+（`rustup` stable 工具链）
- **Node.js** 18+（含 npm）
- **MSVC Build Tools**
- **管理员权限**（运行时需要，用于抓包）

## 快速开始

```bash
# 安装前端依赖
npm install

# 开发模式运行（需要管理员权限）
npm run tauri dev

# 运行测试
cd src-tauri && cargo test    # 43 项 Rust 单元测试
npm test                       # 31 项前端单元测试

# 构建生产安装包
npm run tauri build
```

## 架构

三层设计：

1. **数据包拦截层** — WinDivert 2.x 用户态抓包/重注入，带签名的内核驱动
2. **核心逻辑层** — Rust：无锁流量统计（DashMap）、令牌桶限速器、进程端口映射（sysinfo + Windows API）
3. **前端层** — Tauri webview 中的 React + Tailwind，通过 IPC 命令和每秒事件推送通信

### 运行模式

| 模式 | 说明 | 风险 |
|------|------|------|
| SNIFF（默认） | 只读数据包副本，仅监控 | 零 |
| INTERCEPT（手动开启） | 捕获并重注入数据包，用于限速/阻断 | 需要管理员权限 |

INTERCEPT 模式通过设置中的"强制执行限制"开关激活。未开启时，限速和阻断规则仅为界面展示。

## 安全性

本应用会拦截实时网络数据包。拦截模式下的 Bug 可能导致主机网络中断。

- **故障开放设计** — 应用崩溃时所有流量正常通过（WinDivert 句柄通过 `Drop` trait 释放）
- **看门狗脚本** — `scripts/watchdog.ps1` 自动终止卡死进程
- **紧急恢复** — `scripts/emergency-recovery.ps1` 一键恢复网络
- **分阶段抓包策略** — 开发时必须按 SNIFF → 窄过滤器 → 完整拦截的顺序推进

详见 `docs/NetGuard_PRD_v1.0.md` 第 8 节。

## 免责声明

本软件仅供在**您拥有或获得明确授权管理的设备**上合法使用。例如：监控个人工作站带宽、管理家庭网络流量优先级，或测试您开发的应用程序。

作者不支持也不对任何滥用行为负责，包括但不限于未经授权的网络拦截、绕过安全控制或违反适用法律。**使用风险自负。** 本软件按"原样"提供，不作任何形式的担保。

## 许可证

基于 Apache License 2.0 许可。详见 [LICENSE](LICENSE)。

### 第三方组件

本项目包含 [WinDivert](https://reqrypt.org/windivert.html)，其采用 **GNU 宽通用公共许可证 v3（LGPLv3）** 授权。WinDivert 在运行时动态加载；NetGuard 其余部分保持 Apache 2.0 许可。详见 WinDivert [LICENSE](https://github.com/basil00/WinDivert/blob/master/LICENSE)。
