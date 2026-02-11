import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { timeRangeSeconds } from "../utils";
import type { TimeRange } from "../utils";
import type { ProcessTrafficSnapshot as ProcessTraffic, TrafficRecord, TrafficSummary } from "../bindings";

export function useChartData(showChart: boolean, selectedPid: number | null, processes: ProcessTraffic[]) {
  const [chartData, setChartData] = useState<TrafficRecord[]>([]);
  const [timeRange, setTimeRange] = useState<TimeRange>("1h");
  const [topConsumers, setTopConsumers] = useState<TrafficSummary[]>([]);

  useEffect(() => {
    if (!showChart) return;
    const now = Math.floor(Date.now() / 1000);
    const from = now - timeRangeSeconds(timeRange);
    const selectedProcess = selectedPid ? processes.find((p) => p.pid === selectedPid) : null;
    invoke<TrafficRecord[]>("get_traffic_history", { fromTimestamp: from, toTimestamp: now, processName: selectedProcess?.name ?? null })
      .then(setChartData).catch(() => setChartData([]));
    invoke<TrafficSummary[]>("get_top_consumers", { fromTimestamp: from, toTimestamp: now, limit: 10 })
      .then(setTopConsumers).catch(() => setTopConsumers([]));
  }, [showChart, selectedPid, timeRange, processes]);

  return { chartData, timeRange, setTimeRange, topConsumers };
}
