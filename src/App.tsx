import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";
import { formatSpeed, formatBytes, parseLimitInput, timeRangeSeconds } from "./utils";
import type { TimeRange } from "./utils";
import type {
  ProcessTrafficSnapshot as ProcessTraffic,
  BandwidthLimit,
  TrafficRecord,
  TrafficSummary,
} from "./bindings";

type SortKey = keyof ProcessTraffic;
type SortDir = "asc" | "desc";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Speed bar gradient for table cells — subtle colored fill proportional to relative speed. */
function speedBarBg(speed: number, maxSpeed: number, color: string): string {
  if (speed <= 0 || maxSpeed <= 0) return "transparent";
  const pct = Math.min((speed / maxSpeed) * 100, 100);
  return `linear-gradient(90deg, ${color}18 0%, ${color}0a ${pct}%, transparent ${pct}%)`;
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

function App() {
  // --- State ---
  const [processes, setProcesses] = useState<ProcessTraffic[]>([]);
  const [sortKey, setSortKey] = useState<SortKey>("download_speed");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [filter, setFilter] = useState("");
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [limits, setLimits] = useState<Record<number, BandwidthLimit>>({});
  const [blockedPids, setBlockedPids] = useState<Set<number>>(new Set());
  const [editingCell, setEditingCell] = useState<{ pid: number; field: "dl" | "ul" } | null>(null);
  const editRef = useRef<HTMLInputElement>(null);

  const [showChart, setShowChart] = useState(false);
  const [chartPinned, setChartPinned] = useState(false);
  const [chartClosed, setChartClosed] = useState(false);
  const [chartData, setChartData] = useState<TrafficRecord[]>([]);
  const [timeRange, setTimeRange] = useState<TimeRange>("1h");
  const [topConsumers, setTopConsumers] = useState<TrafficSummary[]>([]);

  const [liveSpeedData, setLiveSpeedData] = useState<{ t: number; dl: number; ul: number }[]>([]);
  const [showPidColumn, setShowPidColumn] = useState(false);

  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; process: ProcessTraffic } | null>(null);

  const [profiles, setProfiles] = useState<string[]>([]);
  const [activeProfile, setActiveProfile] = useState<string | null>(null);
  const [showProfileInput, setShowProfileInput] = useState(false);
  const [profileInput, setProfileInput] = useState("");
  const profileInputRef = useRef<HTMLInputElement>(null);

  const [showSettings, setShowSettings] = useState(false);
  const [notifThreshold, setNotifThreshold] = useState(0);
  const [autostart, setAutostart] = useState(false);
  const [interceptActive, setInterceptActive] = useState(false);

  const [icons, setIcons] = useState<Record<string, string>>({});
  const iconRequested = useRef<Set<string>>(new Set());

  // --- Effects ---

  useEffect(() => {
    const unlisten = listen<ProcessTraffic[]>("traffic-stats", (event) => {
      setProcesses(event.payload);
    });
    return () => { unlisten.then((fn) => fn()); };
  }, []);

  useEffect(() => {
    invoke<ProcessTraffic[]>("get_traffic_stats").then(setProcesses);
    invoke<Record<number, BandwidthLimit>>("get_bandwidth_limits").then(setLimits);
    invoke<number[]>("get_blocked_pids").then((pids) => setBlockedPids(new Set(pids)));
    invoke<string[]>("list_profiles").then(setProfiles).catch(() => {});
    invoke<number>("get_notification_threshold").then(setNotifThreshold).catch(() => {});
    invoke<boolean>("get_autostart").then(setAutostart).catch(() => {});
    invoke<boolean>("is_intercept_active").then(setInterceptActive).catch(() => {});
  }, []);

  useEffect(() => {
    const unlisten = listen<{ pid: number; name: string; speed: number; threshold: number }>(
      "threshold-exceeded",
      (event) => {
        const { name, speed } = event.payload;
        if ("Notification" in window && Notification.permission === "granted") {
          new Notification("NetGuard: Bandwidth Alert", { body: `${name} is using ${formatSpeed(speed)}` });
        } else if ("Notification" in window && Notification.permission !== "denied") {
          Notification.requestPermission().then((perm) => {
            if (perm === "granted") {
              new Notification("NetGuard: Bandwidth Alert", { body: `${name} is using ${formatSpeed(speed)}` });
            }
          });
        }
      }
    );
    return () => { unlisten.then((fn) => fn()); };
  }, []);

  useEffect(() => { editRef.current?.focus(); editRef.current?.select(); }, [editingCell]);
  useEffect(() => { if (showProfileInput) profileInputRef.current?.focus(); }, [showProfileInput]);

  useEffect(() => {
    if (selectedPid === null) { setLiveSpeedData([]); return; }
    const proc = processes.find((p) => p.pid === selectedPid);
    if (!proc) return;
    setLiveSpeedData((prev) => {
      const now = Date.now() / 1000;
      const entry = { t: now, dl: proc.download_speed, ul: proc.upload_speed };
      const cutoff = now - 60;
      return [...prev.filter((d) => d.t > cutoff), entry];
    });
  }, [processes, selectedPid]);

  useEffect(() => {
    const close = () => setContextMenu(null);
    document.addEventListener("click", close);
    return () => document.removeEventListener("click", close);
  }, []);

  useEffect(() => {
    const newPaths = processes
      .map((p) => p.exe_path)
      .filter((path) => path && !(path in icons) && !iconRequested.current.has(path));
    const unique = [...new Set(newPaths)];
    unique.slice(0, 10).forEach((path) => {
      iconRequested.current.add(path);
      invoke<string | null>("get_process_icon", { exePath: path })
        .then((icon) => { if (icon) setIcons((prev) => ({ ...prev, [path]: icon })); })
        .catch(() => {});
    });
  }, [processes, icons]);

  useEffect(() => {
    if (!showChart) return;
    const now = Math.floor(Date.now() / 1000);
    const from = now - timeRangeSeconds(timeRange);
    const selectedProcess = selectedPid ? processes.find((p) => p.pid === selectedPid) : null;
    invoke<TrafficRecord[]>("get_traffic_history", { fromTimestamp: from, toTimestamp: now, processName: selectedProcess?.name ?? null })
      .then(setChartData).catch(() => setChartData([]));
    invoke<TrafficSummary[]>("get_top_consumers", { fromTimestamp: from, toTimestamp: now, limit: 10 })
      .then(setTopConsumers).catch(() => setTopConsumers([]));
  }, [showChart, selectedPid, timeRange, processes]);

  // --- Callbacks ---

  const handleSort = useCallback((key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setSortDir("desc"); }
  }, [sortKey]);

  const applyLimit = useCallback(async (pid: number, field: "dl" | "ul", value: string) => {
    const bps = parseLimitInput(value);
    const existing = limits[pid] || { download_bps: 0, upload_bps: 0 };
    const newLimit = {
      download_bps: field === "dl" ? (bps ?? 0) : existing.download_bps,
      upload_bps: field === "ul" ? (bps ?? 0) : existing.upload_bps,
    };
    if (newLimit.download_bps === 0 && newLimit.upload_bps === 0) {
      await invoke("remove_bandwidth_limit", { pid });
      setLimits((prev) => { const next = { ...prev }; delete next[pid]; return next; });
    } else {
      await invoke("set_bandwidth_limit", { pid, downloadBps: newLimit.download_bps, uploadBps: newLimit.upload_bps });
      setLimits((prev) => ({ ...prev, [pid]: newLimit }));
    }
    setEditingCell(null);
  }, [limits]);

  const toggleBlock = useCallback(async (pid: number) => {
    if (blockedPids.has(pid)) {
      await invoke("unblock_process", { pid });
      setBlockedPids((prev) => { const next = new Set(prev); next.delete(pid); return next; });
    } else {
      await invoke("block_process", { pid });
      setBlockedPids((prev) => new Set(prev).add(pid));
    }
  }, [blockedPids]);

  const handleContextMenu = useCallback((e: React.MouseEvent, process: ProcessTraffic) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, process });
  }, []);

  const copyToClipboard = useCallback((text: string) => {
    navigator.clipboard.writeText(text).catch(() => {});
    setContextMenu(null);
  }, []);

  const saveProfile = useCallback(async (name: string) => {
    if (!name.trim()) return;
    await invoke("save_profile", { profileName: name.trim() });
    const updated = await invoke<string[]>("list_profiles");
    setProfiles(updated);
    setActiveProfile(name.trim());
    setShowProfileInput(false);
    setProfileInput("");
  }, []);

  const applyProfile = useCallback(async (name: string) => {
    await invoke<number>("apply_profile", { profileName: name });
    setActiveProfile(name);
    const [newLimits, newBlocked] = await Promise.all([
      invoke<Record<number, BandwidthLimit>>("get_bandwidth_limits"),
      invoke<number[]>("get_blocked_pids"),
    ]);
    setLimits(newLimits);
    setBlockedPids(new Set(newBlocked));
  }, []);

  const deleteProfile = useCallback(async (name: string) => {
    await invoke("delete_profile", { profileName: name });
    const updated = await invoke<string[]>("list_profiles");
    setProfiles(updated);
    if (activeProfile === name) setActiveProfile(null);
  }, [activeProfile]);

  // --- Computed ---

  const sorted = [...processes]
    .filter((p) => !filter || p.name.toLowerCase().includes(filter.toLowerCase()) || p.pid.toString().includes(filter))
    .sort((a, b) => {
      const av = a[sortKey]; const bv = b[sortKey];
      if (typeof av === "number" && typeof bv === "number") return sortDir === "asc" ? av - bv : bv - av;
      return sortDir === "asc" ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
    });

  const sortIcon = (key: SortKey) => sortKey === key ? (sortDir === "asc" ? " \u25B2" : " \u25BC") : "";
  const totalDown = processes.reduce((s, p) => s + p.download_speed, 0);
  const totalUp = processes.reduce((s, p) => s + p.upload_speed, 0);
  const maxDl = Math.max(...sorted.map((p) => p.download_speed), 1);
  const maxUl = Math.max(...sorted.map((p) => p.upload_speed), 1);
  const colCount = showPidColumn ? 10 : 9;

  // =========================================================================
  // JSX
  // =========================================================================

  return (
    <main className="h-screen flex flex-col bg-ground text-fg font-display overflow-hidden">

      {/* ── Header ────────────────────────────────────────────────── */}
      <header className="flex items-center gap-4 px-4 py-2.5 bg-panel">
        <div className="flex items-center gap-2.5">
          <h1 className="text-lg font-bold tracking-tight">
            <span className="text-neon">Net</span><span className="text-fg">Guard</span>
          </h1>
          {(totalDown + totalUp > 0) && (
            <span className="w-1.5 h-1.5 rounded-full bg-dl animate-pulse-dot" />
          )}
        </div>

        <div className="h-4 w-px bg-subtle mx-1" />

        <div className="flex items-center gap-4 font-mono text-sm">
          <span className="text-dl flex items-center gap-1.5">
            <svg width="10" height="10" viewBox="0 0 10 10" className="opacity-60"><path d="M5 2 L5 8 M2 5 L5 8 L8 5" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round"/></svg>
            {formatSpeed(totalDown)}
          </span>
          <span className="text-ul flex items-center gap-1.5">
            <svg width="10" height="10" viewBox="0 0 10 10" className="opacity-60"><path d="M5 8 L5 2 M2 5 L5 2 L8 5" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round"/></svg>
            {formatSpeed(totalUp)}
          </span>
        </div>

        <div className="flex-1" />

        <button
          onClick={() => setShowSettings((v) => !v)}
          className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all duration-150 ${
            showSettings
              ? "bg-neon/15 text-neon border border-neon/30"
              : "bg-raised text-dim border border-subtle hover:text-fg hover:border-muted"
          }`}
        >
          Settings
        </button>
        <button
          onClick={() => { setShowChart((v) => !v); setChartClosed(false); }}
          className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all duration-150 ${
            showChart
              ? "bg-iris/15 text-iris border border-iris/30"
              : "bg-raised text-dim border border-subtle hover:text-fg hover:border-muted"
          }`}
        >
          History
        </button>

        <div className="relative">
          <input
            type="text"
            placeholder={"Filter processes\u2026"}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="pl-8 pr-3 py-1.5 text-sm rounded-md bg-raised border border-subtle text-fg placeholder-faint focus:outline-none focus:border-neon/50 focus:bg-overlay w-52 transition-colors"
          />
          <svg className="absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        </div>
      </header>
      <div className="accent-line" />

      {/* ── Intercept Mode Banner ─────────────────────────────────── */}
      {interceptActive && (
        <div className="flex items-center gap-2 px-4 py-1.5 bg-caution/8 border-b border-caution/15">
          <span className="w-1.5 h-1.5 rounded-full bg-caution animate-pulse-dot" />
          <span className="text-caution text-xs font-semibold tracking-wide uppercase">Intercept Active</span>
          <span className="text-caution/50 text-xs">Rate limits and blocks are enforced on live traffic</span>
        </div>
      )}

      {/* ── Profile Bar ───────────────────────────────────────────── */}
      {(profiles.length > 0 || showProfileInput) && (
        <div className="flex items-center gap-2 px-4 py-1.5 bg-panel/60 border-b border-subtle/50 text-xs">
          <span className="text-faint font-medium uppercase tracking-wider text-[10px]">Profiles</span>
          <div className="h-3 w-px bg-subtle mx-0.5" />
          {profiles.map((p) => (
            <span key={p} className="inline-flex items-center gap-0.5">
              <button
                onClick={() => applyProfile(p)}
                className={`px-2.5 py-1 rounded-md transition-all duration-150 font-medium ${
                  activeProfile === p
                    ? "bg-iris/15 text-iris border border-iris/30"
                    : "bg-raised text-dim border border-transparent hover:text-fg hover:bg-overlay"
                }`}
              >
                {p}
              </button>
              <button
                onClick={() => deleteProfile(p)}
                className="text-faint hover:text-danger transition-colors px-0.5"
                title={`Delete "${p}"`}
              >&times;</button>
            </span>
          ))}
          {showProfileInput ? (
            <input
              ref={profileInputRef}
              type="text"
              value={profileInput}
              onChange={(e) => setProfileInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") saveProfile(profileInput);
                if (e.key === "Escape") { setShowProfileInput(false); setProfileInput(""); }
              }}
              onBlur={() => { setShowProfileInput(false); setProfileInput(""); }}
              placeholder={"Profile name\u2026"}
              className="px-2 py-1 text-xs rounded-md bg-raised border border-iris/50 text-fg focus:outline-none w-28"
            />
          ) : (
            <button
              onClick={() => setShowProfileInput(true)}
              className="px-2.5 py-1 rounded-md bg-raised text-dim border border-transparent hover:text-fg hover:bg-overlay transition-all"
            >
              + Save Current
            </button>
          )}
        </div>
      )}

      {/* ── Settings Panel ────────────────────────────────────────── */}
      {showSettings && (
        <div className="animate-slide-down border-b border-subtle/50">
          <div className="mx-3 my-2 p-3 bg-raised/80 rounded-lg border border-subtle">
            <div className="flex items-center gap-8 text-xs flex-wrap">
              {/* Bandwidth threshold */}
              <div className="flex items-center gap-2">
                <span className="text-dim">Alert threshold</span>
                <input
                  type="text"
                  defaultValue={notifThreshold > 0 ? (notifThreshold >= 1024 * 1024 ? `${(notifThreshold / (1024 * 1024)).toFixed(1)}m` : `${Math.round(notifThreshold / 1024)}`) : ""}
                  placeholder="e.g. 500 or 5m"
                  className="px-2 py-1 text-xs rounded-md bg-overlay border border-subtle text-fg focus:outline-none focus:border-neon/50 w-24 font-mono"
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      const bps = parseLimitInput(e.currentTarget.value);
                      const val = bps ?? 0;
                      setNotifThreshold(val);
                      invoke("set_notification_threshold", { thresholdBps: val });
                    }
                  }}
                  onBlur={(e) => {
                    const bps = parseLimitInput(e.currentTarget.value);
                    const val = bps ?? 0;
                    setNotifThreshold(val);
                    invoke("set_notification_threshold", { thresholdBps: val });
                  }}
                />
                <span className="text-faint">{notifThreshold > 0 ? formatSpeed(notifThreshold) : "off"}</span>
              </div>

              <div className="h-4 w-px bg-subtle" />

              {/* Show PID */}
              <SettingToggle label="Show PID" on={showPidColumn} onToggle={() => setShowPidColumn((v) => !v)} color="#00d8ff" />

              <div className="h-4 w-px bg-subtle" />

              {/* Autostart */}
              <SettingToggle
                label="Start on login"
                on={autostart}
                onToggle={async () => {
                  const next = !autostart;
                  await invoke("set_autostart", { enabled: next }).catch(() => {});
                  setAutostart(next);
                }}
                color="#00d8ff"
              />

              <div className="h-4 w-px bg-subtle" />

              {/* Enforce limits */}
              <div className="flex items-center gap-2">
                <span className={interceptActive ? "text-caution font-medium" : "text-dim"}>Enforce limits</span>
                <Toggle
                  on={interceptActive}
                  color={interceptActive ? "#ffb020" : undefined}
                  onToggle={async () => {
                    try {
                      if (interceptActive) {
                        await invoke("disable_intercept_mode");
                        setInterceptActive(false);
                      } else {
                        await invoke("enable_intercept_mode", { filter: null });
                        setInterceptActive(true);
                      }
                    } catch (e) {
                      console.error("Intercept toggle failed:", e);
                    }
                  }}
                />
                {interceptActive && <span className="text-caution text-[10px] font-semibold uppercase tracking-wider">Active</span>}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Process Table ─────────────────────────────────────────── */}
      <div className="flex-1 min-h-0 overflow-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10 bg-panel border-b border-subtle">
            <tr>
              <Th onClick={() => handleSort("name")} align="left">Process{sortIcon("name")}</Th>
              {showPidColumn && <Th onClick={() => handleSort("pid")} align="right" width="w-20">PID{sortIcon("pid")}</Th>}
              <Th onClick={() => handleSort("download_speed")} align="right" width="w-28">Download{sortIcon("download_speed")}</Th>
              <Th onClick={() => handleSort("upload_speed")} align="right" width="w-28">Upload{sortIcon("upload_speed")}</Th>
              <Th onClick={() => handleSort("bytes_recv")} align="right" width="w-24">Total DL{sortIcon("bytes_recv")}</Th>
              <Th onClick={() => handleSort("bytes_sent")} align="right" width="w-24">Total UL{sortIcon("bytes_sent")}</Th>
              <Th onClick={() => handleSort("connection_count")} align="right" width="w-14">Conns{sortIcon("connection_count")}</Th>
              <th className="px-3 py-2 text-[10px] font-semibold text-faint uppercase tracking-wider w-24 text-right">DL Limit</th>
              <th className="px-3 py-2 text-[10px] font-semibold text-faint uppercase tracking-wider w-24 text-right">UL Limit</th>
              <th className="px-3 py-2 text-[10px] font-semibold text-faint uppercase tracking-wider w-14 text-center">Block</th>
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 && (
              <tr>
                <td colSpan={colCount} className="px-4 py-16 text-center">
                  <div className="text-faint/40 text-3xl mb-2">{processes.length === 0 ? "\u25C9" : "\u2205"}</div>
                  <div className="text-dim text-sm">
                    {processes.length === 0 ? "Listening for network activity\u2026" : "No matching processes"}
                  </div>
                </td>
              </tr>
            )}
            {sorted.map((p, i) => {
              const limit = limits[p.pid];
              const isBlocked = blockedPids.has(p.pid);
              const isSelected = selectedPid === p.pid;
              const rowState = isBlocked ? "is-blocked" : isSelected ? "is-selected" : limit ? "is-limited" : "";

              return (
                <tr
                  key={p.pid}
                  onClick={() => { setSelectedPid((prev) => (prev === p.pid ? null : p.pid)); setChartClosed(false); }}
                  onContextMenu={(e) => handleContextMenu(e, p)}
                  className={`row-state ${rowState} border-b border-subtle/30 cursor-pointer ${i % 2 === 0 ? "bg-panel/20" : ""}`}
                >
                  {/* Process name + icon */}
                  <td className="px-3 py-1.5 truncate max-w-xs" title={p.exe_path}>
                    <div className="flex items-center gap-2">
                      {icons[p.exe_path] ? (
                        <img src={icons[p.exe_path]} className="w-4 h-4 shrink-0 rounded-sm" alt="" />
                      ) : (
                        <span className="w-4 h-4 shrink-0 rounded-sm bg-subtle" />
                      )}
                      <span className="truncate font-medium text-fg/90">{p.name}</span>
                    </div>
                  </td>

                  {/* PID */}
                  {showPidColumn && (
                    <td className="px-3 py-1.5 text-right data-cell text-faint text-xs">{p.pid}</td>
                  )}

                  {/* Download speed + bar */}
                  <td
                    className="px-3 py-1.5 text-right data-cell text-dl text-xs"
                    style={{ background: speedBarBg(p.download_speed, maxDl, "#00e68a") }}
                  >
                    {formatSpeed(p.download_speed)}
                  </td>

                  {/* Upload speed + bar */}
                  <td
                    className="px-3 py-1.5 text-right data-cell text-ul text-xs"
                    style={{ background: speedBarBg(p.upload_speed, maxUl, "#3b9eff") }}
                  >
                    {formatSpeed(p.upload_speed)}
                  </td>

                  {/* Totals */}
                  <td className="px-3 py-1.5 text-right data-cell text-dim text-xs">{formatBytes(p.bytes_recv)}</td>
                  <td className="px-3 py-1.5 text-right data-cell text-dim text-xs">{formatBytes(p.bytes_sent)}</td>

                  {/* Connections */}
                  <td className="px-3 py-1.5 text-right data-cell text-faint text-xs">{p.connection_count}</td>

                  {/* Limit cells */}
                  <LimitCell
                    pid={p.pid} field="dl" currentBps={limit?.download_bps ?? 0}
                    editing={editingCell} editRef={editRef}
                    onStartEdit={(pid, field) => setEditingCell({ pid, field })}
                    onApply={applyLimit} onCancel={() => setEditingCell(null)}
                  />
                  <LimitCell
                    pid={p.pid} field="ul" currentBps={limit?.upload_bps ?? 0}
                    editing={editingCell} editRef={editRef}
                    onStartEdit={(pid, field) => setEditingCell({ pid, field })}
                    onApply={applyLimit} onCancel={() => setEditingCell(null)}
                  />

                  {/* Block toggle */}
                  <td className="px-3 py-1.5 text-center" onClick={(e) => e.stopPropagation()}>
                    <Toggle
                      on={isBlocked}
                      onToggle={() => toggleBlock(p.pid)}
                      color={isBlocked ? "#ff4757" : undefined}
                    />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* ── Pinnable Chart Panel ─────────────────────────────────── */}
      {/* Visible when: history open, OR chart pinned, OR (process selected with live data AND not dismissed) */}
      {(showChart || (chartPinned && !showChart) || (!chartClosed && selectedPid !== null && liveSpeedData.length > 1)) && (
        <div className={`border-t border-subtle bg-panel flex flex-col animate-slide-up shrink-0 ${showChart ? "h-56" : "h-40"}`}>
          {/* Chart toolbar */}
          <div className="flex items-center gap-2 px-4 py-1 border-b border-subtle/50 shrink-0">
            {/* Left: label */}
            <span className="text-xs text-dim font-medium truncate">
              {showChart
                ? (selectedPid ? `History: ${processes.find((p) => p.pid === selectedPid)?.name ?? `PID ${selectedPid}`}` : "History: All Processes")
                : selectedPid
                  ? `Live: ${processes.find((p) => p.pid === selectedPid)?.name ?? `PID ${selectedPid}`}`
                  : "Chart pinned"
              }
            </span>

            {!showChart && selectedPid !== null && <span className="text-[10px] text-faint uppercase tracking-wider ml-1">60s</span>}

            <div className="flex-1" />

            {/* Time range selector (history mode) */}
            {showChart && (
              <div className="flex gap-1 mr-2">
                {(["1h", "24h", "7d", "30d"] as TimeRange[]).map((r) => (
                  <button
                    key={r}
                    onClick={() => setTimeRange(r)}
                    className={`px-2 py-0.5 text-[10px] font-semibold uppercase rounded transition-all duration-150 ${
                      timeRange === r
                        ? "bg-iris/15 text-iris border border-iris/30"
                        : "text-faint hover:text-dim hover:bg-overlay"
                    }`}
                  >
                    {r}
                  </button>
                ))}
              </div>
            )}

            {/* Pin button — only for live chart mode (not history) */}
            {!showChart && (
              <button
                onClick={() => setChartPinned((v) => !v)}
                className={`p-1 rounded transition-colors ${chartPinned ? "text-neon" : "text-faint hover:text-dim"}`}
                title={chartPinned ? "Unpin chart" : "Pin chart"}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  {chartPinned ? (
                    <><path d="M12 17v5"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></>
                  ) : (
                    <><path d="M12 17v5"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/><line x1="2" y1="2" x2="22" y2="22"/></>
                  )}
                </svg>
              </button>
            )}

            {/* Close button */}
            <button
              onClick={() => { setShowChart(false); setChartPinned(false); setChartClosed(true); }}
              className="p-1 rounded text-faint hover:text-danger transition-colors"
              title="Close chart"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>

          {/* Chart content */}
          <div className="flex-1 flex min-h-0">
            {/* Live chart — only when NOT in history mode */}
            {!showChart && selectedPid !== null && liveSpeedData.length > 1 && (
              <div className="flex-1 px-2 py-1 flex flex-col">
                <div className="flex-1">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={liveSpeedData}>
                      <defs>
                        <linearGradient id="liveDlGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#00e68a" stopOpacity={0.25} />
                          <stop offset="95%" stopColor="#00e68a" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="liveUlGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#3b9eff" stopOpacity={0.2} />
                          <stop offset="95%" stopColor="#3b9eff" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#2e3d52" strokeOpacity={0.4} />
                      <XAxis dataKey="t" tick={false} stroke="#2e3d52" />
                      <YAxis tick={{ fontSize: 9, fill: "#5c7492", fontFamily: "JetBrains Mono" }} tickFormatter={(v: number) => formatSpeed(v)} width={60} stroke="#2e3d52" />
                      <Area type="monotone" dataKey="dl" stroke="#00e68a" fill="url(#liveDlGrad)" strokeWidth={1.5} dot={false} isAnimationActive={false} name="DL" />
                      <Area type="monotone" dataKey="ul" stroke="#3b9eff" fill="url(#liveUlGrad)" strokeWidth={1.5} dot={false} isAnimationActive={false} name="UL" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {/* Pinned empty state — chart pinned but no process selected */}
            {!showChart && (selectedPid === null || liveSpeedData.length <= 1) && chartPinned && (
              <div className="flex-1 flex items-center justify-center">
                <span className="text-faint text-sm">Select a process to view live speed</span>
              </div>
            )}

            {/* History chart (only in history mode) */}
            {showChart && (
              <div className="flex-1 px-2 py-1">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartData}>
                    <defs>
                      <linearGradient id="histDlGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#00e68a" stopOpacity={0.25} />
                        <stop offset="95%" stopColor="#00e68a" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="histUlGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#3b9eff" stopOpacity={0.2} />
                        <stop offset="95%" stopColor="#3b9eff" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2e3d52" strokeOpacity={0.4} />
                    <XAxis
                      dataKey="timestamp"
                      tick={{ fontSize: 9, fill: "#5c7492", fontFamily: "JetBrains Mono" }}
                      tickFormatter={(ts: number) => new Date(ts * 1000).toLocaleTimeString()}
                      stroke="#2e3d52"
                    />
                    <YAxis tick={{ fontSize: 9, fill: "#5c7492", fontFamily: "JetBrains Mono" }} tickFormatter={(v: number) => formatSpeed(v)} width={68} stroke="#2e3d52" />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#1c2636",
                        border: "1px solid #2e3d52",
                        borderRadius: "8px",
                        fontSize: "11px",
                        fontFamily: "JetBrains Mono",
                        boxShadow: "0 8px 24px rgba(0,0,0,0.5)",
                      }}
                      labelStyle={{ color: "#99adc4" }}
                      labelFormatter={(ts: number) => new Date(ts * 1000).toLocaleString()}
                      formatter={(v: number) => formatSpeed(v)}
                    />
                    <Area type="monotone" dataKey="download_speed" stroke="#00e68a" fill="url(#histDlGrad)" strokeWidth={1.5} dot={false} name="Download" />
                    <Area type="monotone" dataKey="upload_speed" stroke="#3b9eff" fill="url(#histUlGrad)" strokeWidth={1.5} dot={false} name="Upload" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* Top consumers sidebar (history mode only) */}
            {showChart && (
              <div className="w-40 border-l border-subtle/50 overflow-auto px-3 py-2">
                <div className="text-[10px] text-faint uppercase tracking-wider font-semibold mb-2">Top Consumers</div>
                {topConsumers.map((c, i) => (
                  <div key={i} className="flex justify-between text-xs py-1 border-b border-subtle/20 last:border-0">
                    <span className="truncate text-dim mr-2">{c.process_name}</span>
                    <span className="text-faint font-mono text-[10px] shrink-0">{formatBytes(c.total_bytes)}</span>
                  </div>
                ))}
                {topConsumers.length === 0 && <div className="text-xs text-faint/50">No data</div>}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Context Menu ──────────────────────────────────────────── */}
      {contextMenu && (
        <div
          className="fixed z-50 bg-raised/95 backdrop-blur-sm border border-subtle rounded-lg shadow-2xl py-1 min-w-[190px] animate-fade-in"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          <CtxItem onClick={() => { setEditingCell({ pid: contextMenu.process.pid, field: "dl" }); setContextMenu(null); }}>
            Set Download Limit
          </CtxItem>
          <CtxItem onClick={() => { setEditingCell({ pid: contextMenu.process.pid, field: "ul" }); setContextMenu(null); }}>
            Set Upload Limit
          </CtxItem>
          {limits[contextMenu.process.pid] && (
            <CtxItem onClick={async () => { await invoke("remove_bandwidth_limit", { pid: contextMenu.process.pid }); setLimits((prev) => { const n = { ...prev }; delete n[contextMenu.process.pid]; return n; }); setContextMenu(null); }}>
              Remove Limits
            </CtxItem>
          )}
          <div className="border-t border-subtle/50 my-1 mx-2" />
          <CtxItem onClick={async () => { await toggleBlock(contextMenu.process.pid); setContextMenu(null); }}>
            {blockedPids.has(contextMenu.process.pid) ? "Unblock" : "Block"}
          </CtxItem>
          <div className="border-t border-subtle/50 my-1 mx-2" />
          <CtxItem onClick={() => copyToClipboard(contextMenu.process.exe_path)}>
            Copy Process Path
          </CtxItem>
          <CtxItem onClick={() => copyToClipboard(contextMenu.process.pid.toString())}>
            Copy PID
          </CtxItem>
        </div>
      )}

      {/* ── Status Bar ────────────────────────────────────────────── */}
      <footer className="flex items-center gap-3 px-4 py-1.5 bg-panel border-t border-subtle text-[11px]">
        <span className="text-faint font-mono">{processes.length} processes</span>
        {sorted.length !== processes.length && (
          <span className="text-dim font-mono">{sorted.length} shown</span>
        )}
        {Object.keys(limits).length > 0 && (
          <Badge color="caution">{Object.keys(limits).length} limited</Badge>
        )}
        {blockedPids.size > 0 && (
          <Badge color="danger">{blockedPids.size} blocked</Badge>
        )}
        <div className="flex-1" />
        {interceptActive && (
          <Badge color="caution">Intercept</Badge>
        )}
      </footer>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function Th({ children, onClick, align = "left", width = "" }: {
  children: React.ReactNode;
  onClick: () => void;
  align?: "left" | "right";
  width?: string;
}) {
  return (
    <th
      onClick={onClick}
      className={`px-3 py-2 text-[10px] font-semibold text-faint uppercase tracking-wider cursor-pointer select-none hover:text-dim transition-colors ${width} ${
        align === "right" ? "text-right" : "text-left"
      }`}
    >
      {children}
    </th>
  );
}

function LimitCell({
  pid, field, currentBps, editing, editRef, onStartEdit, onApply, onCancel,
}: {
  pid: number; field: "dl" | "ul"; currentBps: number;
  editing: { pid: number; field: "dl" | "ul" } | null;
  editRef: React.RefObject<HTMLInputElement | null>;
  onStartEdit: (pid: number, field: "dl" | "ul") => void;
  onApply: (pid: number, field: "dl" | "ul", value: string) => void;
  onCancel: () => void;
}) {
  const isEditing = editing?.pid === pid && editing?.field === field;
  if (isEditing) {
    return (
      <td className="px-2 py-0.5 text-right" onClick={(e) => e.stopPropagation()}>
        <input
          ref={editRef}
          type="text"
          defaultValue={currentBps > 0 ? (currentBps >= 1024 * 1024 ? `${(currentBps / (1024 * 1024)).toFixed(1)}m` : `${Math.round(currentBps / 1024)}`) : ""}
          placeholder="KB/s"
          className="w-20 px-2 py-0.5 text-xs text-right rounded-md bg-overlay border border-neon/40 text-fg font-mono focus:outline-none focus:border-neon"
          onKeyDown={(e) => {
            if (e.key === "Enter") onApply(pid, field, e.currentTarget.value);
            if (e.key === "Escape") onCancel();
            if (e.key === "Delete" || (e.key === "Backspace" && !e.currentTarget.value)) onApply(pid, field, "");
          }}
          onBlur={(e) => onApply(pid, field, e.currentTarget.value)}
        />
      </td>
    );
  }
  return (
    <td
      className="px-3 py-1.5 text-right font-mono"
      onDoubleClick={(e) => { e.stopPropagation(); onStartEdit(pid, field); }}
    >
      {currentBps > 0 ? (
        <span className="text-caution text-xs">
          {currentBps >= 1024 * 1024 ? `${(currentBps / (1024 * 1024)).toFixed(1)} MB/s` : `${Math.round(currentBps / 1024)} KB/s`}
        </span>
      ) : (
        <span className="text-faint/40 text-xs">{"\u2014"}</span>
      )}
    </td>
  );
}

function Toggle({ on, onToggle, color }: { on: boolean; onToggle: () => void; color?: string }) {
  return (
    <button
      onClick={onToggle}
      className={`toggle-track ${on ? "is-on" : ""}`}
      style={on && color ? { backgroundColor: color, boxShadow: `0 0 8px ${color}40` } : { backgroundColor: on ? "#00d8ff" : "#3d4f68" }}
    >
      <span className="toggle-thumb" />
    </button>
  );
}

function SettingToggle({ label, on, onToggle, color }: { label: string; on: boolean; onToggle: () => void; color?: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-dim">{label}</span>
      <Toggle on={on} onToggle={onToggle} color={on ? color : undefined} />
    </div>
  );
}

function Badge({ children, color }: { children: React.ReactNode; color: "caution" | "danger" | "neon" | "iris" }) {
  const colorMap = {
    caution: "bg-caution/10 text-caution border-caution/20",
    danger: "bg-danger/10 text-danger border-danger/20",
    neon: "bg-neon/10 text-neon border-neon/20",
    iris: "bg-iris/10 text-iris border-iris/20",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full border text-[10px] font-semibold ${colorMap[color]}`}>
      {children}
    </span>
  );
}

function CtxItem({ children, onClick }: { children: React.ReactNode; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left px-3 py-1.5 text-xs text-dim hover:bg-overlay hover:text-fg transition-colors rounded-sm mx-0.5"
    >
      {children}
    </button>
  );
}

export default App;
