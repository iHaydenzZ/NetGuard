import type { ProcessTrafficSnapshot as ProcessTraffic, TrafficRecord, TrafficSummary } from "../bindings";
import type { TimeRange } from "../utils";
import { HistoryChart, HistoryChartContent, TopConsumersSidebar } from "./HistoryChart";
import { LiveSpeedChart, LiveSpeedToolbarLabel } from "./LiveSpeedChart";

interface ChartPanelProps {
  showChart: boolean;
  chartPinned: boolean;
  setChartPinned: (fn: (v: boolean) => boolean) => void;
  setShowChart: (v: boolean) => void;
  setChartClosed: (v: boolean) => void;
  chartData: TrafficRecord[];
  timeRange: TimeRange;
  setTimeRange: (r: TimeRange) => void;
  topConsumers: TrafficSummary[];
  selectedPid: number | null;
  processes: ProcessTraffic[];
  liveSpeedData: { t: number; dl: number; ul: number }[];
}

export function ChartPanel({
  showChart, chartPinned, setChartPinned, setShowChart, setChartClosed,
  chartData, timeRange, setTimeRange, topConsumers,
  selectedPid, processes, liveSpeedData,
}: ChartPanelProps) {
  return (
    <div className={`border-t border-subtle bg-panel flex flex-col animate-slide-up shrink-0 ${showChart ? "h-56" : "h-40"}`}>
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-4 py-1 border-b border-subtle/50 shrink-0">
        {showChart ? (
          <HistoryChart timeRange={timeRange} setTimeRange={setTimeRange} selectedPid={selectedPid} processes={processes} />
        ) : (
          <>
            <LiveSpeedToolbarLabel selectedPid={selectedPid} processes={processes} />
            <div className="flex-1" />
          </>
        )}

        {/* Pin button */}
        {!showChart && (
          <button
            onClick={() => setChartPinned((v) => !v)}
            className={`p-1 rounded transition-colors ${chartPinned ? "text-neon" : "text-faint hover:text-dim"}`}
            title={chartPinned ? "Unpin chart" : "Pin chart"}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              {chartPinned ? (
                <><path d="M12 17v5"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></>
              ) : (
                <><path d="M12 17v5"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/><line x1="2" y1="2" x2="22" y2="22"/></>
              )}
            </svg>
          </button>
        )}

        {/* Close button */}
        <button
          onClick={() => { setShowChart(false); setChartPinned(() => false); setChartClosed(true); }}
          className="p-1 rounded text-faint hover:text-danger transition-colors"
          title="Close chart"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>

      {/* Chart content */}
      <div className="flex-1 flex min-h-0">
        {!showChart && selectedPid !== null && liveSpeedData.length > 1 && (
          <LiveSpeedChart liveSpeedData={liveSpeedData} selectedPid={selectedPid} />
        )}

        {!showChart && (selectedPid === null || liveSpeedData.length <= 1) && chartPinned && (
          <div className="flex-1 flex items-center justify-center">
            <span className="text-faint text-sm">Select a process to view live speed</span>
          </div>
        )}

        {showChart && (
          <>
            <HistoryChartContent chartData={chartData} />
            <TopConsumersSidebar topConsumers={topConsumers} />
          </>
        )}
      </div>
    </div>
  );
}
