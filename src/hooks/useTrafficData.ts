import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { parseBandwidthInput } from "../utils";
import type {
  ProcessTrafficSnapshot as ProcessTraffic,
  BandwidthLimit,
} from "../bindings";

export type SortKey = keyof ProcessTraffic;
export type SortDir = "asc" | "desc";

// Give up fetching an exe's icon after this many null/error results. The
// backend returns null both for a transient miss (PID exited mid-resolution)
// and for an exe with no extractable icon; without a cap, a resident icon-less
// exe would be re-requested on every traffic-stats tick for the whole session.
export const MAX_ICON_ATTEMPTS = 3;

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
  const iconAttempts = useRef<Map<string, number>>(new Map());
  const [limitInputError, setLimitInputError] = useState<string | null>(null);
  const [controlError, setControlError] = useState<string | null>(null);

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

  // Fetch icons for new processes.
  // Dedup by exe_path so processes sharing an executable reuse one cache entry.
  // We pass the PID to the backend — the backend resolves the path from its own
  // ProcessMapper, eliminating the arbitrary-path IPC surface.
  useEffect(() => {
    // Build a map from exe_path -> first available pid for paths not yet fetched.
    const pathToPid = new Map<string, number>();
    for (const p of processes) {
      if (p.exe_path && !(p.exe_path in icons) && !iconRequested.current.has(p.exe_path)) {
        if (!pathToPid.has(p.exe_path)) {
          pathToPid.set(p.exe_path, p.pid);
        }
      }
    }
    [...pathToPid.entries()].slice(0, 10).forEach(([path, pid]) => {
      // Mark requested before the call to dedup concurrent in-flight requests
      // for the same exe across rapid re-renders. On a transient miss (null) or
      // error — e.g. the PID exited between the snapshot and resolution — clear
      // the marker so a later process sharing this exe can retry, but only up
      // to MAX_ICON_ATTEMPTS: the backend can't distinguish a transient miss
      // from an exe with no extractable icon, and an uncapped retry would
      // re-request a resident icon-less exe on every stats tick.
      iconRequested.current.add(path);
      const retryOrGiveUp = () => {
        const attempts = (iconAttempts.current.get(path) ?? 0) + 1;
        iconAttempts.current.set(path, attempts);
        if (attempts < MAX_ICON_ATTEMPTS) iconRequested.current.delete(path);
      };
      invoke<string | null>("get_process_icon", { pid })
        .then((icon) => {
          if (icon) setIcons((prev) => ({ ...prev, [path]: icon }));
          else retryOrGiveUp();
        })
        .catch(retryOrGiveUp);
    });
  }, [processes, icons]);

  // Sort handler
  const handleSort = useCallback((key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setSortDir("desc"); }
  }, [sortKey]);

  // Surface a rejected control command (block/limit) in the status bar.
  // Backend guards (e.g. reserved PIDs 0/4) reject with a message; without
  // this the rejection would be an unhandled promise and the UI would lie.
  const controlErrorTimer = useRef<number | null>(null);
  useEffect(() => () => {
    // Don't let a pending auto-clear fire after unmount.
    if (controlErrorTimer.current !== null) clearTimeout(controlErrorTimer.current);
  }, []);
  const reportControlError = useCallback((e: unknown) => {
    const msg = e && typeof e === "object" && "message" in e
      ? String((e as { message: unknown }).message)
      : String(e);
    setControlError(msg);
    // Replace (not stack) the auto-clear timer on rapid repeated failures.
    if (controlErrorTimer.current !== null) clearTimeout(controlErrorTimer.current);
    controlErrorTimer.current = window.setTimeout(() => setControlError(null), 4000);
  }, []);

  // Apply a bandwidth limit
  const applyLimit = useCallback(async (pid: number, field: "dl" | "ul", value: string) => {
    const parsed = parseBandwidthInput(value);
    if (parsed.kind === "invalid") {
      setLimitInputError("Invalid input — enter a number like 500k, 5m, or 1.5mb");
      return; // Keep existing limit; do not close the cell
    }
    setLimitInputError(null);
    const bps = parsed.kind === "value" ? parsed.bps : 0; // empty → clear (0)
    const existing = limits[pid] || { download_bps: 0, upload_bps: 0 };
    const newLimit = {
      download_bps: field === "dl" ? bps : existing.download_bps,
      upload_bps: field === "ul" ? bps : existing.upload_bps,
    };
    try {
      if (newLimit.download_bps === 0 && newLimit.upload_bps === 0) {
        await invoke("remove_bandwidth_limit", { pid });
        setLimits((prev) => { const next = { ...prev }; delete next[pid]; return next; });
      } else {
        await invoke("set_bandwidth_limit", { pid, downloadBps: newLimit.download_bps, uploadBps: newLimit.upload_bps });
        setLimits((prev) => ({ ...prev, [pid]: newLimit }));
      }
    } catch (e: unknown) {
      // Backend rejected the rule (e.g. reserved PID): keep local state
      // unchanged and surface the message instead of swallowing it.
      reportControlError(e);
    }
    setEditingCell(null);
  }, [limits, reportControlError]);

  // Toggle process block
  const toggleBlock = useCallback(async (pid: number) => {
    try {
      if (blockedPids.has(pid)) {
        await invoke("unblock_process", { pid });
        setBlockedPids((prev) => { const next = new Set(prev); next.delete(pid); return next; });
      } else {
        await invoke("block_process", { pid });
        setBlockedPids((prev) => new Set(prev).add(pid));
      }
      setControlError(null);
    } catch (e: unknown) {
      reportControlError(e);
    }
  }, [blockedPids, reportControlError]);

  // Remove all limits for a PID (context menu action) with error surfacing.
  const removeLimits = useCallback(async (pid: number) => {
    try {
      await invoke("remove_bandwidth_limit", { pid });
      setLimits((prev) => { const next = { ...prev }; delete next[pid]; return next; });
    } catch (e: unknown) {
      reportControlError(e);
    }
  }, [reportControlError]);

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
    removeLimits,
    sorted,
    totalDown,
    totalUp,
    maxDl,
    maxUl,
    colCount,
    sortIcon,
    limitInputError,
    setLimitInputError,
    controlError,
    setControlError,
  };
}
