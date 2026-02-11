import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";
import { formatSpeed } from "../utils";
import type { ProcessTrafficSnapshot as ProcessTraffic } from "../bindings";

export interface LiveSpeedChartProps {
  liveSpeedData: { t: number; dl: number; ul: number }[];
  selectedPid: number | null;
}

export function LiveSpeedChart({ liveSpeedData, selectedPid }: LiveSpeedChartProps) {
  if (selectedPid === null || liveSpeedData.length <= 1) return null;
  return (
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
  );
}

export function LiveSpeedToolbarLabel({ selectedPid, processes }: {
  selectedPid: number | null;
  processes: ProcessTraffic[];
}) {
  const label = selectedPid
    ? `Live: ${processes.find((p) => p.pid === selectedPid)?.name ?? `PID ${selectedPid}`}`
    : "Chart pinned";
  return (
    <>
      <span className="text-xs text-dim font-medium truncate">{label}</span>
      {selectedPid !== null && <span className="text-[10px] text-faint uppercase tracking-wider ml-1">60s</span>}
    </>
  );
}
