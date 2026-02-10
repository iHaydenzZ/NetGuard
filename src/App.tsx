import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

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

type SortKey = keyof ProcessTraffic;
type SortDir = "asc" | "desc";

function formatSpeed(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`;
  if (bytesPerSec < 1024 * 1024)
    return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSec / (1024 * 1024)).toFixed(2)} MB/s`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/** Parse a user input like "500" (KB/s) or "1.5m" (MB/s) to bytes/sec. */
function parseLimitInput(input: string): number | null {
  const trimmed = input.trim().toLowerCase();
  if (!trimmed) return null;
  const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(k|m|kb|mb)?$/);
  if (!match) return null;
  const value = parseFloat(match[1]);
  const unit = match[2] || "k";
  if (unit.startsWith("m")) return Math.round(value * 1024 * 1024);
  return Math.round(value * 1024); // default KB/s
}

function App() {
  const [processes, setProcesses] = useState<ProcessTraffic[]>([]);
  const [sortKey, setSortKey] = useState<SortKey>("download_speed");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [filter, setFilter] = useState("");
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [limits, setLimits] = useState<Record<number, BandwidthLimit>>({});
  const [editingCell, setEditingCell] = useState<{
    pid: number;
    field: "dl" | "ul";
  } | null>(null);
  const editRef = useRef<HTMLInputElement>(null);

  // Listen for traffic-stats events from the Rust backend (1s interval).
  useEffect(() => {
    const unlisten = listen<ProcessTraffic[]>("traffic-stats", (event) => {
      setProcesses(event.payload);
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  // Fetch initial data and limits.
  useEffect(() => {
    invoke<ProcessTraffic[]>("get_traffic_stats").then(setProcesses);
    invoke<Record<number, BandwidthLimit>>("get_bandwidth_limits").then(
      setLimits
    );
  }, []);

  // Focus the edit input when it appears.
  useEffect(() => {
    editRef.current?.focus();
    editRef.current?.select();
  }, [editingCell]);

  const handleSort = useCallback(
    (key: SortKey) => {
      if (sortKey === key) {
        setSortDir((d) => (d === "asc" ? "desc" : "asc"));
      } else {
        setSortKey(key);
        setSortDir("desc");
      }
    },
    [sortKey]
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
        setLimits((prev) => {
          const next = { ...prev };
          delete next[pid];
          return next;
        });
      } else {
        await invoke("set_bandwidth_limit", {
          pid,
          downloadBps: newLimit.download_bps,
          uploadBps: newLimit.upload_bps,
        });
        setLimits((prev) => ({ ...prev, [pid]: newLimit }));
      }
      setEditingCell(null);
    },
    [limits]
  );

  const sorted = [...processes]
    .filter(
      (p) =>
        !filter ||
        p.name.toLowerCase().includes(filter.toLowerCase()) ||
        p.pid.toString().includes(filter)
    )
    .sort((a, b) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      if (typeof av === "number" && typeof bv === "number") {
        return sortDir === "asc" ? av - bv : bv - av;
      }
      return sortDir === "asc"
        ? String(av).localeCompare(String(bv))
        : String(bv).localeCompare(String(av));
    });

  const sortIndicator = (key: SortKey) =>
    sortKey === key ? (sortDir === "asc" ? " ▲" : " ▼") : "";

  const totalDown = processes.reduce((s, p) => s + p.download_speed, 0);
  const totalUp = processes.reduce((s, p) => s + p.upload_speed, 0);

  return (
    <main className="min-h-screen bg-gray-950 text-gray-200 flex flex-col">
      {/* Toolbar */}
      <header className="flex items-center gap-4 px-4 py-2 bg-gray-900 border-b border-gray-800">
        <h1 className="text-lg font-semibold text-white tracking-tight">
          NetGuard
        </h1>
        <span className="text-xs text-gray-500">|</span>
        <div className="flex gap-3 text-sm">
          <span className="text-green-400">
            ↓ {formatSpeed(totalDown)}
          </span>
          <span className="text-blue-400">
            ↑ {formatSpeed(totalUp)}
          </span>
        </div>
        <div className="flex-1" />
        <input
          type="text"
          placeholder="Filter processes..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="px-3 py-1 text-sm rounded bg-gray-800 border border-gray-700 text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 w-56"
        />
      </header>

      {/* Process Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-gray-900 border-b border-gray-800">
            <tr>
              <Th onClick={() => handleSort("name")}>
                Process{sortIndicator("name")}
              </Th>
              <Th onClick={() => handleSort("pid")} className="w-20 text-right">
                PID{sortIndicator("pid")}
              </Th>
              <Th
                onClick={() => handleSort("download_speed")}
                className="w-28 text-right"
              >
                Download{sortIndicator("download_speed")}
              </Th>
              <Th
                onClick={() => handleSort("upload_speed")}
                className="w-28 text-right"
              >
                Upload{sortIndicator("upload_speed")}
              </Th>
              <Th
                onClick={() => handleSort("bytes_recv")}
                className="w-28 text-right"
              >
                Total DL{sortIndicator("bytes_recv")}
              </Th>
              <Th
                onClick={() => handleSort("bytes_sent")}
                className="w-28 text-right"
              >
                Total UL{sortIndicator("bytes_sent")}
              </Th>
              <Th
                onClick={() => handleSort("connection_count")}
                className="w-16 text-right"
              >
                Conns{sortIndicator("connection_count")}
              </Th>
              <th className="px-4 py-2 text-xs font-medium text-gray-400 uppercase tracking-wider w-24 text-right">
                DL Limit
              </th>
              <th className="px-4 py-2 text-xs font-medium text-gray-400 uppercase tracking-wider w-24 text-right">
                UL Limit
              </th>
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 && (
              <tr>
                <td
                  colSpan={9}
                  className="px-4 py-8 text-center text-gray-500"
                >
                  {processes.length === 0
                    ? "Waiting for network activity..."
                    : "No matching processes"}
                </td>
              </tr>
            )}
            {sorted.map((p) => {
              const limit = limits[p.pid];
              return (
                <tr
                  key={p.pid}
                  onClick={() =>
                    setSelectedPid((prev) =>
                      prev === p.pid ? null : p.pid
                    )
                  }
                  className={`border-b border-gray-800/50 cursor-pointer transition-colors ${
                    selectedPid === p.pid
                      ? "bg-blue-900/30"
                      : "hover:bg-gray-800/50"
                  }`}
                >
                  <td
                    className="px-4 py-1.5 truncate max-w-xs"
                    title={p.exe_path}
                  >
                    {p.name}
                  </td>
                  <td className="px-4 py-1.5 text-right text-gray-400 tabular-nums">
                    {p.pid}
                  </td>
                  <td className="px-4 py-1.5 text-right text-green-400 tabular-nums">
                    {formatSpeed(p.download_speed)}
                  </td>
                  <td className="px-4 py-1.5 text-right text-blue-400 tabular-nums">
                    {formatSpeed(p.upload_speed)}
                  </td>
                  <td className="px-4 py-1.5 text-right text-gray-400 tabular-nums">
                    {formatBytes(p.bytes_recv)}
                  </td>
                  <td className="px-4 py-1.5 text-right text-gray-400 tabular-nums">
                    {formatBytes(p.bytes_sent)}
                  </td>
                  <td className="px-4 py-1.5 text-right text-gray-400 tabular-nums">
                    {p.connection_count}
                  </td>
                  {/* DL Limit */}
                  <LimitCell
                    pid={p.pid}
                    field="dl"
                    currentBps={limit?.download_bps ?? 0}
                    editing={editingCell}
                    editRef={editRef}
                    onStartEdit={(pid, field) =>
                      setEditingCell({ pid, field })
                    }
                    onApply={applyLimit}
                    onCancel={() => setEditingCell(null)}
                  />
                  {/* UL Limit */}
                  <LimitCell
                    pid={p.pid}
                    field="ul"
                    currentBps={limit?.upload_bps ?? 0}
                    editing={editingCell}
                    editRef={editRef}
                    onStartEdit={(pid, field) =>
                      setEditingCell({ pid, field })
                    }
                    onApply={applyLimit}
                    onCancel={() => setEditingCell(null)}
                  />
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Status bar */}
      <footer className="flex items-center gap-4 px-4 py-1.5 bg-gray-900 border-t border-gray-800 text-xs text-gray-500">
        <span>{processes.length} processes</span>
        <span>
          {sorted.length !== processes.length && `${sorted.length} shown`}
        </span>
        {Object.keys(limits).length > 0 && (
          <span className="text-yellow-500">
            {Object.keys(limits).length} limited
          </span>
        )}
      </footer>
    </main>
  );
}

function LimitCell({
  pid,
  field,
  currentBps,
  editing,
  editRef,
  onStartEdit,
  onApply,
  onCancel,
}: {
  pid: number;
  field: "dl" | "ul";
  currentBps: number;
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
          defaultValue={
            currentBps > 0
              ? currentBps >= 1024 * 1024
                ? `${(currentBps / (1024 * 1024)).toFixed(1)}m`
                : `${Math.round(currentBps / 1024)}`
              : ""
          }
          placeholder="KB/s"
          className="w-20 px-1.5 py-0.5 text-xs text-right rounded bg-gray-800 border border-blue-500 text-white focus:outline-none"
          onKeyDown={(e) => {
            if (e.key === "Enter") onApply(pid, field, e.currentTarget.value);
            if (e.key === "Escape") onCancel();
          }}
          onBlur={(e) => onApply(pid, field, e.currentTarget.value)}
        />
      </td>
    );
  }

  return (
    <td
      className="px-4 py-1.5 text-right tabular-nums"
      onDoubleClick={(e) => {
        e.stopPropagation();
        onStartEdit(pid, field);
      }}
    >
      {currentBps > 0 ? (
        <span className="text-yellow-400 text-xs">
          {currentBps >= 1024 * 1024
            ? `${(currentBps / (1024 * 1024)).toFixed(1)} MB/s`
            : `${Math.round(currentBps / 1024)} KB/s`}
        </span>
      ) : (
        <span className="text-gray-600 text-xs">--</span>
      )}
    </td>
  );
}

function Th({
  children,
  onClick,
  className = "",
}: {
  children: React.ReactNode;
  onClick: () => void;
  className?: string;
}) {
  return (
    <th
      onClick={onClick}
      className={`px-4 py-2 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer select-none hover:text-white transition-colors ${className}`}
    >
      {children}
    </th>
  );
}

export default App;
