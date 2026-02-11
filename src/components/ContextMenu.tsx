import { invoke } from "@tauri-apps/api/core";
import { CtxItem } from "./ui/CtxItem";
import type { ProcessTrafficSnapshot as ProcessTraffic, BandwidthLimit } from "../bindings";

export interface ContextMenuProps {
  contextMenu: { x: number; y: number; process: ProcessTraffic } | null;
  limits: Record<number, BandwidthLimit>;
  blockedPids: Set<number>;
  setEditingCell: (cell: { pid: number; field: "dl" | "ul" } | null) => void;
  setLimits: React.Dispatch<React.SetStateAction<Record<number, BandwidthLimit>>>;
  toggleBlock: (pid: number) => void;
  setContextMenu: (menu: { x: number; y: number; process: ProcessTraffic } | null) => void;
}

export function ContextMenu({
  contextMenu,
  limits,
  blockedPids,
  setEditingCell,
  setLimits,
  toggleBlock,
  setContextMenu,
}: ContextMenuProps) {
  if (!contextMenu) return null;

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).catch(() => {});
    setContextMenu(null);
  };

  return (
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
  );
}
