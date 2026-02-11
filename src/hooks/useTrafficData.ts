import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { parseLimitInput } from "../utils";
import type {
  ProcessTrafficSnapshot as ProcessTraffic,
  BandwidthLimit,
} from "../bindings";

export type SortKey = keyof ProcessTraffic;
export type SortDir = "asc" | "desc";

export function useTrafficData() {
  const [processes, setProcesses] = useState<ProcessTraffic[]>([]);
  const [sortKey, setSortKey] = useState<SortKey>("download_speed");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [filter, setFilter] = useState("");
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [limits, setLimits] = useState<Record<number, BandwidthLimit>>({});
  const [blockedPids, setBlockedPids] = useState<Set<number>>(new Set());
  const [editingCell, setEditingCell] = useState<{ pid: number; field: "dl" | "ul" } | null>(null);
  const editRef = useRef<HTMLInputElement>(null);

  const [liveSpeedData, setLiveSpeedData] = useState<{ t: number; dl: number; ul: number }[]>([]);
  const [showPidColumn, setShowPidColumn] = useState(false);

  const [icons, setIcons] = useState<Record<string, string>>({});
  const iconRequested = useRef<Set<string>>(new Set());

  // Listen to traffic-stats events
  useEffect(() => {
    const unlisten = listen<ProcessTraffic[]>("traffic-stats", (event) => {
      setProcesses(event.payload);
    });
    return () => { unlisten.then((fn) => fn()); };
  }, []);

  // Initial data fetch
  useEffect(() => {
    invoke<ProcessTraffic[]>("get_traffic_stats").then(setProcesses);
    invoke<Record<number, BandwidthLimit>>("get_bandwidth_limits").then(setLimits);
    invoke<number[]>("get_blocked_pids").then((pids) => setBlockedPids(new Set(pids)));
  }, []);

  // Focus edit input when editing starts
  useEffect(() => { editRef.current?.focus(); editRef.current?.select(); }, [editingCell]);

  // Accumulate live speed data for selected process
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

  // Fetch icons for new processes
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

  // Sort handler
  const handleSort = useCallback((key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setSortDir("desc"); }
  }, [sortKey]);

  // Apply a bandwidth limit
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

  // Toggle process block
  const toggleBlock = useCallback(async (pid: number) => {
    if (blockedPids.has(pid)) {
      await invoke("unblock_process", { pid });
      setBlockedPids((prev) => { const next = new Set(prev); next.delete(pid); return next; });
    } else {
      await invoke("block_process", { pid });
      setBlockedPids((prev) => new Set(prev).add(pid));
    }
  }, [blockedPids]);

  // Computed values
  const sorted = [...processes]
    .filter((p) => !filter || p.name.toLowerCase().includes(filter.toLowerCase()) || p.pid.toString().includes(filter))
    .sort((a, b) => {
      const av = a[sortKey]; const bv = b[sortKey];
      if (typeof av === "number" && typeof bv === "number") return sortDir === "asc" ? av - bv : bv - av;
      return sortDir === "asc" ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
    });

  const totalDown = processes.reduce((s, p) => s + p.download_speed, 0);
  const totalUp = processes.reduce((s, p) => s + p.upload_speed, 0);
  const maxDl = Math.max(...sorted.map((p) => p.download_speed), 1);
  const maxUl = Math.max(...sorted.map((p) => p.upload_speed), 1);
  const colCount = showPidColumn ? 10 : 9;

  const sortIcon = (key: SortKey) => sortKey === key ? (sortDir === "asc" ? " \u25B2" : " \u25BC") : "";

  return {
    processes,
    sortKey,
    sortDir,
    filter,
    setFilter,
    selectedPid,
    setSelectedPid,
    limits,
    setLimits,
    blockedPids,
    setBlockedPids,
    editingCell,
    setEditingCell,
    editRef,
    liveSpeedData,
    showPidColumn,
    setShowPidColumn,
    icons,
    handleSort,
    applyLimit,
    toggleBlock,
    sorted,
    totalDown,
    totalUp,
    maxDl,
    maxUl,
    colCount,
    sortIcon,
  };
}
