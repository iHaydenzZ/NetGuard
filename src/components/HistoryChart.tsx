import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";
import { formatSpeed, formatBytes } from "../utils";
import type { TimeRange } from "../utils";
import type { TrafficRecord, TrafficSummary } from "../bindings";
import type { ProcessTrafficSnapshot as ProcessTraffic } from "../bindings";

export interface HistoryChartProps {
  timeRange: TimeRange;
  setTimeRange: (r: TimeRange) => void;
  selectedPid: number | null;
  processes: ProcessTraffic[];
}

export function HistoryChart({
  timeRange,
  setTimeRange,
  selectedPid,
  processes,
}: HistoryChartProps) {
  return (
    <>
      {/* Chart toolbar additions: label + time range selector */}
      <HistoryToolbarLabel selectedPid={selectedPid} processes={processes} />
      <div className="flex-1" />
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
    </>
  );
}

function HistoryToolbarLabel({ selectedPid, processes }: { selectedPid: number | null; processes: ProcessTraffic[] }) {
  const label = selectedPid
    ? `History: ${processes.find((p) => p.pid === selectedPid)?.name ?? `PID ${selectedPid}`}`
    : "History: All Processes";
  return <span className="text-xs text-dim font-medium truncate">{label}</span>;
}

export function HistoryChartContent({ chartData }: { chartData: TrafficRecord[] }) {
  return (
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
  );
}

export function TopConsumersSidebar({ topConsumers }: { topConsumers: TrafficSummary[] }) {
  return (
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
  );
}
