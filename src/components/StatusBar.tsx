import { Badge } from "./ui/Badge";
import type { BandwidthLimit } from "../bindings";

interface StatusBarProps {
  processCount: number;
  shownCount: number;
  limits: Record<number, BandwidthLimit>;
  blockedPids: Set<number>;
  interceptActive: boolean;
  controlError?: string | null;
}

export function StatusBar({ processCount, shownCount, limits, blockedPids, interceptActive, controlError }: StatusBarProps) {
  const limitCount = Object.keys(limits).length;
  const blockCount = blockedPids.size;

  return (
    <footer className="flex items-center gap-3 px-4 py-1.5 bg-panel border-t border-subtle text-[11px]">
      <span className="text-faint font-mono">{processCount} processes</span>
      {shownCount !== processCount && (
        <span className="text-dim font-mono">{shownCount} shown</span>
      )}
      {limitCount > 0 && (
        interceptActive
          ? <Badge color="caution">{limitCount} limited</Badge>
          : <Badge color="caution">{limitCount} pending {limitCount === 1 ? "limit" : "limits"}</Badge>
      )}
      {blockCount > 0 && (
        interceptActive
          ? <Badge color="danger">{blockCount} blocked</Badge>
          : <Badge color="danger">{blockCount} pending {blockCount === 1 ? "block" : "blocks"}</Badge>
      )}
      {controlError && (
        <span className="text-danger text-[10px]">{controlError}</span>
      )}
      <div className="flex-1" />
      {interceptActive && (
        <Badge color="caution">Intercept</Badge>
      )}
    </footer>
  );
}
