import { formatSpeed, formatBytes } from "../utils";
import { Th } from "./ui/Th";
import { LimitCell } from "./ui/LimitCell";
import { Toggle } from "./ui/Toggle";
import type { ProcessTrafficSnapshot as ProcessTraffic, BandwidthLimit } from "../bindings";
import type { SortKey } from "../hooks/useTrafficData";

export interface ProcessTableProps {
  sorted: ProcessTraffic[];
  processCount: number;
  limits: Record<number, BandwidthLimit>;
  blockedPids: Set<number>;
  icons: Record<string, string>;
  showPidColumn: boolean;
  editingCell: { pid: number; field: "dl" | "ul" } | null;
  editRef: React.RefObject<HTMLInputElement | null>;
  colCount: number;
  maxDl: number;
  maxUl: number;
  selectedPid: number | null;
  sortIcon: (key: SortKey) => string;
  handleSort: (key: SortKey) => void;
  setEditingCell: (cell: { pid: number; field: "dl" | "ul" } | null) => void;
  applyLimit: (pid: number, field: "dl" | "ul", value: string) => void;
  toggleBlock: (pid: number) => void;
  setSelectedPid: (pid: number | null) => void;
  handleContextMenu: (e: React.MouseEvent, process: ProcessTraffic) => void;
  setChartClosed: (v: boolean) => void;
}

/** Speed bar gradient for table cells. */
function speedBarBg(speed: number, maxSpeed: number, color: string): string {
  if (speed <= 0 || maxSpeed <= 0) return "transparent";
  const pct = Math.min((speed / maxSpeed) * 100, 100);
  return `linear-gradient(90deg, ${color}18 0%, ${color}0a ${pct}%, transparent ${pct}%)`;
}

export function ProcessTable({
  sorted,
  processCount,
  limits,
  blockedPids,
  icons,
  showPidColumn,
  editingCell,
  editRef,
  colCount,
  maxDl,
  maxUl,
  selectedPid,
  sortIcon,
  handleSort,
  setEditingCell,
  applyLimit,
  toggleBlock,
  setSelectedPid,
  handleContextMenu,
  setChartClosed,
}: ProcessTableProps) {
  return (
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
                <div className="text-faint/40 text-3xl mb-2">{processCount === 0 ? "\u25C9" : "\u2205"}</div>
                <div className="text-dim text-sm">
                  {processCount === 0 ? "Listening for network activity\u2026" : "No matching processes"}
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
                onClick={() => { setSelectedPid(selectedPid === p.pid ? null : p.pid); setChartClosed(false); }}
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
  );
}
