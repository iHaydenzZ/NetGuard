import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { formatSpeed, formatBytes, parseLimitInput, timeRangeSeconds } from "./utils";
import type { TimeRange } from "./utils";

interface ProcessTraffic {
  pid: number;
  name: string;
  exe_path: string;
  upload_speed: number;
  download_speed: number;
  bytes_sent: number;
  bytes_recv: number;
  connection_count: number;
}

interface BandwidthLimit {
  download_bps: number;
  upload_bps: number;
}

interface TrafficRecord {
  timestamp: number;
  pid: number;
  process_name: string;
  exe_path: string;
  bytes_sent: number;
  bytes_recv: number;
  upload_speed: number;
  download_speed: number;
}

interface TrafficSummary {
  process_name: string;
  exe_path: string;
  total_sent: number;
  total_recv: number;
  total_bytes: number;
}

type SortKey = keyof ProcessTraffic;
type SortDir = "asc" | "desc";

function App() {
  const [processes, setProcesses] = useState<ProcessTraffic[]>([]);
  const [sortKey, setSortKey] = useState<SortKey>("download_speed");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [filter, setFilter] = useState("");
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [limits, setLimits] = useState<Record<number, BandwidthLimit>>({});
  const [blockedPids, setBlockedPids] = useState<Set<number>>(new Set());
  const [editingCell, setEditingCell] = useState<{
    pid: number;
    field: "dl" | "ul";
  } | null>(null);
  const editRef = useRef<HTMLInputElement>(null);

  // Chart state
  const [showChart, setShowChart] = useState(false);
  const [chartData, setChartData] = useState<TrafficRecord[]>([]);
  const [timeRange, setTimeRange] = useState<TimeRange>("1h");
  const [topConsumers, setTopConsumers] = useState<TrafficSummary[]>([]);

  // Real-time speed buffer for selected process (PRD 5.3: live speed graph on row click).
  const [liveSpeedData, setLiveSpeedData] = useState<{ t: number; dl: number; ul: number }[]>([]);

  // Column visibility (PRD 5.2: PID hidden by default)
  const [showPidColumn, setShowPidColumn] = useState(false);

  // Context menu state (PRD 5.3)
  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    process: ProcessTraffic;
  } | null>(null);

  // Profile state (F5)
  const [profiles, setProfiles] = useState<string[]>([]);
  const [activeProfile, setActiveProfile] = useState<string | null>(null);
  const [showProfileInput, setShowProfileInput] = useState(false);
  const [profileInput, setProfileInput] = useState("");
  const profileInputRef = useRef<HTMLInputElement>(null);

  // Settings state (AC-6.4 + F7)
  const [showSettings, setShowSettings] = useState(false);
  const [notifThreshold, setNotifThreshold] = useState(0);
  const [autostart, setAutostart] = useState(false);

  // Process icon cache (AC-1.6): exe_path -> base64 data URI.
  const [icons, setIcons] = useState<Record<string, string>>({});
  // Track paths we've already requested so we don't re-fetch failures.
  const iconRequested = useRef<Set<string>>(new Set());

  // Listen for traffic-stats events.
  useEffect(() => {
    const unlisten = listen<ProcessTraffic[]>("traffic-stats", (event) => {
      setProcesses(event.payload);
    });
    return () => { unlisten.then((fn) => fn()); };
  }, []);

  // Fetch initial data.
  useEffect(() => {
    invoke<ProcessTraffic[]>("get_traffic_stats").then(setProcesses);
    invoke<Record<number, BandwidthLimit>>("get_bandwidth_limits").then(setLimits);
    invoke<number[]>("get_blocked_pids").then((pids) => setBlockedPids(new Set(pids)));
    invoke<string[]>("list_profiles").then(setProfiles).catch(() => {});
    invoke<number>("get_notification_threshold").then(setNotifThreshold).catch(() => {});
    invoke<boolean>("get_autostart").then(setAutostart).catch(() => {});
  }, []);

  // Listen for threshold-exceeded notifications (AC-6.4).
  useEffect(() => {
    const unlisten = listen<{ pid: number; name: string; speed: number; threshold: number }>(
      "threshold-exceeded",
      (event) => {
        const { name, speed } = event.payload;
        if ("Notification" in window && Notification.permission === "granted") {
          new Notification("NetGuard: Bandwidth Alert", {
            body: `${name} is using ${formatSpeed(speed)}`,
          });
        } else if ("Notification" in window && Notification.permission !== "denied") {
          Notification.requestPermission().then((perm) => {
            if (perm === "granted") {
              new Notification("NetGuard: Bandwidth Alert", {
                body: `${name} is using ${formatSpeed(speed)}`,
              });
            }
          });
        }
      }
    );
    return () => { unlisten.then((fn) => fn()); };
  }, []);

  // Focus edit input.
  useEffect(() => {
    editRef.current?.focus();
    editRef.current?.select();
  }, [editingCell]);

  // Focus profile input when shown.
  useEffect(() => {
    if (showProfileInput) {
      profileInputRef.current?.focus();
    }
  }, [showProfileInput]);

  // Accumulate live speed samples for the selected process (PRD 5.3).
  useEffect(() => {
    if (selectedPid === null) { setLiveSpeedData([]); return; }
    const proc = processes.find((p) => p.pid === selectedPid);
    if (!proc) return;
    setLiveSpeedData((prev) => {
      const now = Date.now() / 1000;
      const entry = { t: now, dl: proc.download_speed, ul: proc.upload_speed };
      const cutoff = now - 60; // keep last 60 seconds
      return [...prev.filter((d) => d.t > cutoff), entry];
    });
  }, [processes, selectedPid]);

  // Close context menu on click anywhere (PRD 5.3).
  useEffect(() => {
    const close = () => setContextMenu(null);
    document.addEventListener("click", close);
    return () => document.removeEventListener("click", close);
  }, []);

  // Fetch process icons for new exe paths (AC-1.6).
  useEffect(() => {
    const newPaths = processes
      .map((p) => p.exe_path)
      .filter((path) => path && !(path in icons) && !iconRequested.current.has(path));
    const unique = [...new Set(newPaths)];
    // Batch up to 10 requests per render cycle to avoid flooding.
    unique.slice(0, 10).forEach((path) => {
      iconRequested.current.add(path);
      invoke<string | null>("get_process_icon", { exePath: path })
        .then((icon) => {
          if (icon) {
            setIcons((prev) => ({ ...prev, [path]: icon }));
          }
        })
        .catch(() => { /* icon extraction failed — leave placeholder */ });
    });
  }, [processes, icons]);

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
    // Refresh limits and blocks from the newly applied profile.
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

  // Fetch chart data when selected process or time range changes.
  useEffect(() => {
    if (!showChart) return;
    const now = Math.floor(Date.now() / 1000);
    const from = now - timeRangeSeconds(timeRange);

    const selectedProcess = selectedPid
      ? processes.find((p) => p.pid === selectedPid)
      : null;

    invoke<TrafficRecord[]>("get_traffic_history", {
      fromTimestamp: from,
      toTimestamp: now,
      processName: selectedProcess?.name ?? null,
    }).then(setChartData).catch(() => setChartData([]));

    invoke<TrafficSummary[]>("get_top_consumers", {
      fromTimestamp: from,
      toTimestamp: now,
      limit: 10,
    }).then(setTopConsumers).catch(() => setTopConsumers([]));
  }, [showChart, selectedPid, timeRange, processes]);

  const handleSort = useCallback(
    (key: SortKey) => {
      if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
      else { setSortKey(key); setSortDir("desc"); }
    }, [sortKey]
  );

  const applyLimit = useCallback(
    async (pid: number, field: "dl" | "ul", value: string) => {
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
    }, [limits]
  );

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

  const sorted = [...processes]
    .filter((p) => !filter || p.name.toLowerCase().includes(filter.toLowerCase()) || p.pid.toString().includes(filter))
    .sort((a, b) => {
      const av = a[sortKey]; const bv = b[sortKey];
      if (typeof av === "number" && typeof bv === "number") return sortDir === "asc" ? av - bv : bv - av;
      return sortDir === "asc" ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
    });

  const sortIndicator = (key: SortKey) => sortKey === key ? (sortDir === "asc" ? " ▲" : " ▼") : "";
  const totalDown = processes.reduce((s, p) => s + p.download_speed, 0);
  const totalUp = processes.reduce((s, p) => s + p.upload_speed, 0);

  return (
    <main className="min-h-screen bg-gray-950 text-gray-200 flex flex-col">
      {/* Toolbar */}
      <header className="flex items-center gap-4 px-4 py-2 bg-gray-900 border-b border-gray-800">
        <h1 className="text-lg font-semibold text-white tracking-tight">NetGuard</h1>
        <span className="text-xs text-gray-500">|</span>
        <div className="flex gap-3 text-sm">
          <span className="text-green-400">↓ {formatSpeed(totalDown)}</span>
          <span className="text-blue-400">↑ {formatSpeed(totalUp)}</span>
        </div>
        <div className="flex-1" />
        <button
          onClick={() => setShowSettings((v) => !v)}
          className={`px-3 py-1 text-xs rounded transition-colors ${showSettings ? "bg-gray-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}
        >
          Settings
        </button>
        <button
          onClick={() => setShowChart((v) => !v)}
          className={`px-3 py-1 text-xs rounded transition-colors ${showChart ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}
        >
          History
        </button>
        <input
          type="text"
          placeholder="Filter processes..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="px-3 py-1 text-sm rounded bg-gray-800 border border-gray-700 text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 w-56"
        />
      </header>

      {/* Profile Bar (F5) */}
      <div className="flex items-center gap-2 px-4 py-1 bg-gray-900/50 border-b border-gray-800 text-xs">
        <span className="text-gray-500">Profiles:</span>
        {profiles.map((p) => (
          <span key={p} className="inline-flex items-center gap-1">
            <button
              onClick={() => applyProfile(p)}
              className={`px-2 py-0.5 rounded transition-colors ${activeProfile === p ? "bg-purple-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}
            >
              {p}
            </button>
            <button
              onClick={() => deleteProfile(p)}
              className="text-gray-600 hover:text-red-400 transition-colors"
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
            placeholder="Profile name..."
            className="px-2 py-0.5 text-xs rounded bg-gray-800 border border-purple-500 text-white focus:outline-none w-32"
          />
        ) : (
          <button
            onClick={() => setShowProfileInput(true)}
            className="px-2 py-0.5 rounded bg-gray-800 text-gray-400 hover:text-white transition-colors"
          >
            + Save Current
          </button>
        )}
      </div>

      {/* Settings Panel */}
      {showSettings && (
        <div className="px-4 py-2 bg-gray-900/70 border-b border-gray-800 flex items-center gap-6 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-gray-400">Bandwidth alert threshold:</span>
            <input
              type="text"
              defaultValue={notifThreshold > 0 ? (notifThreshold >= 1024 * 1024 ? `${(notifThreshold / (1024 * 1024)).toFixed(1)}m` : `${Math.round(notifThreshold / 1024)}`) : ""}
              placeholder="e.g. 500 KB/s or 5m"
              className="px-2 py-0.5 text-xs rounded bg-gray-800 border border-gray-700 text-white focus:outline-none focus:border-blue-500 w-28"
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
            <span className="text-gray-500">{notifThreshold > 0 ? `(${formatSpeed(notifThreshold)})` : "(disabled)"}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-gray-400">Show PID:</span>
            <button
              onClick={() => setShowPidColumn((v) => !v)}
              className={`w-8 h-4 rounded-full transition-colors relative ${showPidColumn ? "bg-green-600" : "bg-gray-700"}`}
            >
              <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-transform ${showPidColumn ? "left-4" : "left-0.5"}`} />
            </button>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-gray-400">Start on login:</span>
            <button
              onClick={async () => {
                const next = !autostart;
                await invoke("set_autostart", { enabled: next }).catch(() => {});
                setAutostart(next);
              }}
              className={`w-8 h-4 rounded-full transition-colors relative ${autostart ? "bg-green-600" : "bg-gray-700"}`}
            >
              <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-transform ${autostart ? "left-4" : "left-0.5"}`} />
            </button>
          </div>
        </div>
      )}

      {/* Process Table */}
      <div className={`${showChart ? "flex-1 min-h-0" : "flex-1"} overflow-auto`}>
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-gray-900 border-b border-gray-800">
            <tr>
              <Th onClick={() => handleSort("name")}>Process{sortIndicator("name")}</Th>
              {showPidColumn && <Th onClick={() => handleSort("pid")} className="w-20 text-right">PID{sortIndicator("pid")}</Th>}
              <Th onClick={() => handleSort("download_speed")} className="w-28 text-right">Download{sortIndicator("download_speed")}</Th>
              <Th onClick={() => handleSort("upload_speed")} className="w-28 text-right">Upload{sortIndicator("upload_speed")}</Th>
              <Th onClick={() => handleSort("bytes_recv")} className="w-28 text-right">Total DL{sortIndicator("bytes_recv")}</Th>
              <Th onClick={() => handleSort("bytes_sent")} className="w-28 text-right">Total UL{sortIndicator("bytes_sent")}</Th>
              <Th onClick={() => handleSort("connection_count")} className="w-16 text-right">Conns{sortIndicator("connection_count")}</Th>
              <th className="px-4 py-2 text-xs font-medium text-gray-400 uppercase tracking-wider w-24 text-right">DL Limit</th>
              <th className="px-4 py-2 text-xs font-medium text-gray-400 uppercase tracking-wider w-24 text-right">UL Limit</th>
              <th className="px-4 py-2 text-xs font-medium text-gray-400 uppercase tracking-wider w-16 text-center">Block</th>
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 && (
              <tr><td colSpan={showPidColumn ? 10 : 9} className="px-4 py-8 text-center text-gray-500">
                {processes.length === 0 ? "Waiting for network activity..." : "No matching processes"}
              </td></tr>
            )}
            {sorted.map((p) => {
              const limit = limits[p.pid];
              const isBlocked = blockedPids.has(p.pid);
              return (
                <tr
                  key={p.pid}
                  onClick={() => setSelectedPid((prev) => (prev === p.pid ? null : p.pid))}
                  onContextMenu={(e) => handleContextMenu(e, p)}
                  className={`border-b border-gray-800/50 cursor-pointer transition-colors ${selectedPid === p.pid ? "bg-blue-900/30" : "hover:bg-gray-800/50"}`}
                >
                  <td className="px-4 py-1.5 truncate max-w-xs flex items-center gap-2" title={p.exe_path}>
                    {icons[p.exe_path] ? (
                      <img src={icons[p.exe_path]} className="w-4 h-4 shrink-0" alt="" />
                    ) : (
                      <span className="w-4 h-4 shrink-0 bg-gray-700 rounded" />
                    )}
                    {p.name}
                  </td>
                  {showPidColumn && <td className="px-4 py-1.5 text-right text-gray-400 tabular-nums">{p.pid}</td>}
                  <td className="px-4 py-1.5 text-right text-green-400 tabular-nums">{formatSpeed(p.download_speed)}</td>
                  <td className="px-4 py-1.5 text-right text-blue-400 tabular-nums">{formatSpeed(p.upload_speed)}</td>
                  <td className="px-4 py-1.5 text-right text-gray-400 tabular-nums">{formatBytes(p.bytes_recv)}</td>
                  <td className="px-4 py-1.5 text-right text-gray-400 tabular-nums">{formatBytes(p.bytes_sent)}</td>
                  <td className="px-4 py-1.5 text-right text-gray-400 tabular-nums">{p.connection_count}</td>
                  <LimitCell pid={p.pid} field="dl" currentBps={limit?.download_bps ?? 0} editing={editingCell} editRef={editRef} onStartEdit={(pid, field) => setEditingCell({ pid, field })} onApply={applyLimit} onCancel={() => setEditingCell(null)} />
                  <LimitCell pid={p.pid} field="ul" currentBps={limit?.upload_bps ?? 0} editing={editingCell} editRef={editRef} onStartEdit={(pid, field) => setEditingCell({ pid, field })} onApply={applyLimit} onCancel={() => setEditingCell(null)} />
                  <td className="px-4 py-1.5 text-center" onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={() => toggleBlock(p.pid)}
                      className={`w-8 h-4 rounded-full transition-colors relative ${isBlocked ? "bg-red-600" : "bg-gray-700"}`}
                      title={isBlocked ? "Unblock" : "Block"}
                    >
                      <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-transform ${isBlocked ? "left-4" : "left-0.5"}`} />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Live Speed Chart — shows when a process is selected (PRD 5.3) */}
      {selectedPid !== null && liveSpeedData.length > 1 && !showChart && (
        <div className="h-32 border-t border-gray-800 bg-gray-900 flex flex-col">
          <div className="flex items-center px-4 py-1 border-b border-gray-800">
            <span className="text-xs text-gray-400">
              Live: {processes.find((p) => p.pid === selectedPid)?.name ?? `PID ${selectedPid}`}
            </span>
            <div className="flex-1" />
            <span className="text-xs text-gray-600">Last 60s</span>
          </div>
          <div className="flex-1 px-2 py-1">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={liveSpeedData}>
                <XAxis dataKey="t" tick={false} />
                <YAxis tick={{ fontSize: 9, fill: "#6b7280" }} tickFormatter={(v: number) => formatSpeed(v)} width={60} />
                <Line type="monotone" dataKey="dl" stroke="#4ade80" dot={false} strokeWidth={1.5} name="DL" isAnimationActive={false} />
                <Line type="monotone" dataKey="ul" stroke="#60a5fa" dot={false} strokeWidth={1.5} name="UL" isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Chart Panel (F4) — historical data */}
      {showChart && (
        <div className="h-64 border-t border-gray-800 bg-gray-900 flex flex-col">
          <div className="flex items-center gap-2 px-4 py-1.5 border-b border-gray-800">
            <span className="text-xs text-gray-400">
              {selectedPid ? `History: ${processes.find((p) => p.pid === selectedPid)?.name ?? `PID ${selectedPid}`}` : "History: All Processes"}
            </span>
            <div className="flex-1" />
            {(["1h", "24h", "7d", "30d"] as TimeRange[]).map((r) => (
              <button
                key={r}
                onClick={() => setTimeRange(r)}
                className={`px-2 py-0.5 text-xs rounded ${timeRange === r ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}
              >
                {r}
              </button>
            ))}
          </div>
          <div className="flex-1 flex min-h-0">
            {/* Live speed mini-chart when process is selected */}
            {selectedPid !== null && liveSpeedData.length > 1 && (
              <div className="w-64 border-r border-gray-800 px-2 py-1 flex flex-col">
                <div className="text-xs text-gray-500 mb-1">Live (60s)</div>
                <div className="flex-1">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={liveSpeedData}>
                      <XAxis dataKey="t" tick={false} />
                      <YAxis tick={{ fontSize: 9, fill: "#6b7280" }} tickFormatter={(v: number) => formatSpeed(v)} width={50} />
                      <Line type="monotone" dataKey="dl" stroke="#4ade80" dot={false} strokeWidth={1} isAnimationActive={false} />
                      <Line type="monotone" dataKey="ul" stroke="#60a5fa" dot={false} strokeWidth={1} isAnimationActive={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}
            <div className="flex-1 px-2 py-1">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData}>
                  <XAxis
                    dataKey="timestamp"
                    tick={{ fontSize: 10, fill: "#6b7280" }}
                    tickFormatter={(ts: number) => new Date(ts * 1000).toLocaleTimeString()}
                  />
                  <YAxis tick={{ fontSize: 10, fill: "#6b7280" }} tickFormatter={(v: number) => formatSpeed(v)} width={70} />
                  <Tooltip
                    contentStyle={{ backgroundColor: "#1f2937", border: "none", borderRadius: "4px", fontSize: "12px" }}
                    labelFormatter={(ts: number) => new Date(ts * 1000).toLocaleString()}
                    formatter={(v: number) => formatSpeed(v)}
                  />
                  <Line type="monotone" dataKey="download_speed" stroke="#4ade80" dot={false} strokeWidth={1.5} name="Download" />
                  <Line type="monotone" dataKey="upload_speed" stroke="#60a5fa" dot={false} strokeWidth={1.5} name="Upload" />
                </LineChart>
              </ResponsiveContainer>
            </div>
            {/* Top consumers sidebar */}
            <div className="w-48 border-l border-gray-800 overflow-auto px-2 py-1">
              <div className="text-xs text-gray-500 uppercase mb-1">Top Consumers</div>
              {topConsumers.map((c, i) => (
                <div key={i} className="flex justify-between text-xs py-0.5">
                  <span className="truncate text-gray-300 mr-2">{c.process_name}</span>
                  <span className="text-gray-500 tabular-nums">{formatBytes(c.total_bytes)}</span>
                </div>
              ))}
              {topConsumers.length === 0 && <div className="text-xs text-gray-600">No data</div>}
            </div>
          </div>
        </div>
      )}

      {/* Context Menu (PRD 5.3) */}
      {contextMenu && (
        <div
          className="fixed z-50 bg-gray-800 border border-gray-700 rounded shadow-lg py-1 min-w-[180px]"
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
          <div className="border-t border-gray-700 my-1" />
          <CtxItem onClick={async () => { await toggleBlock(contextMenu.process.pid); setContextMenu(null); }}>
            {blockedPids.has(contextMenu.process.pid) ? "Unblock" : "Block"}
          </CtxItem>
          <div className="border-t border-gray-700 my-1" />
          <CtxItem onClick={() => copyToClipboard(contextMenu.process.exe_path)}>
            Copy Process Path
          </CtxItem>
          <CtxItem onClick={() => copyToClipboard(contextMenu.process.pid.toString())}>
            Copy PID
          </CtxItem>
        </div>
      )}

      {/* Status bar */}
      <footer className="flex items-center gap-4 px-4 py-1.5 bg-gray-900 border-t border-gray-800 text-xs text-gray-500">
        <span>{processes.length} processes</span>
        {sorted.length !== processes.length && <span>{sorted.length} shown</span>}
        {Object.keys(limits).length > 0 && <span className="text-yellow-500">{Object.keys(limits).length} limited</span>}
        {blockedPids.size > 0 && <span className="text-red-500">{blockedPids.size} blocked</span>}
      </footer>
    </main>
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
        <input ref={editRef} type="text"
          defaultValue={currentBps > 0 ? (currentBps >= 1024 * 1024 ? `${(currentBps / (1024 * 1024)).toFixed(1)}m` : `${Math.round(currentBps / 1024)}`) : ""}
          placeholder="KB/s"
          className="w-20 px-1.5 py-0.5 text-xs text-right rounded bg-gray-800 border border-blue-500 text-white focus:outline-none"
          onKeyDown={(e) => { if (e.key === "Enter") onApply(pid, field, e.currentTarget.value); if (e.key === "Escape") onCancel(); }}
          onBlur={(e) => onApply(pid, field, e.currentTarget.value)}
        />
      </td>
    );
  }
  return (
    <td className="px-4 py-1.5 text-right tabular-nums" onDoubleClick={(e) => { e.stopPropagation(); onStartEdit(pid, field); }}>
      {currentBps > 0
        ? <span className="text-yellow-400 text-xs">{currentBps >= 1024 * 1024 ? `${(currentBps / (1024 * 1024)).toFixed(1)} MB/s` : `${Math.round(currentBps / 1024)} KB/s`}</span>
        : <span className="text-gray-600 text-xs">--</span>}
    </td>
  );
}

function Th({ children, onClick, className = "" }: { children: React.ReactNode; onClick: () => void; className?: string }) {
  return (
    <th onClick={onClick} className={`px-4 py-2 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer select-none hover:text-white transition-colors ${className}`}>
      {children}
    </th>
  );
}

function CtxItem({ children, onClick }: { children: React.ReactNode; onClick: () => void }) {
  return (
    <button onClick={onClick} className="w-full text-left px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700 hover:text-white transition-colors">
      {children}
    </button>
  );
}

export default App;
