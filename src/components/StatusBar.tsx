import { Badge } from "./ui/Badge";
import type { BandwidthLimit } from "../bindings";

interface StatusBarProps {
  processCount: number;
  shownCount: number;
  limits: Record<number, BandwidthLimit>;
  blockedPids: Set<number>;
  interceptActive: boolean;
}

export function StatusBar({ processCount, shownCount, limits, blockedPids, interceptActive }: StatusBarProps) {
  return (
    <footer className="flex items-center gap-3 px-4 py-1.5 bg-panel border-t border-subtle text-[11px]">
      <span className="text-faint font-mono">{processCount} processes</span>
      {shownCount !== processCount && (
        <span className="text-dim font-mono">{shownCount} shown</span>
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
  );
}
