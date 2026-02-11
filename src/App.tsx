import { useState, useEffect, useCallback } from "react";
import type { ProcessTrafficSnapshot as ProcessTraffic } from "./bindings";
import { useTrafficData } from "./hooks/useTrafficData";
import { useProfiles } from "./hooks/useProfiles";
import { useSettings } from "./hooks/useSettings";
import { useChartData } from "./hooks/useChartData";
import { Header } from "./components/Header";
import { ProcessTable } from "./components/ProcessTable";
import { SettingsPanel } from "./components/SettingsPanel";
import { ProfileBar } from "./components/ProfileBar";
import { ContextMenu } from "./components/ContextMenu";
import { ChartPanel } from "./components/ChartPanel";
import { StatusBar } from "./components/StatusBar";

function App() {
  const traffic = useTrafficData();
  const settings = useSettings();
  const profiles = useProfiles({ setLimits: traffic.setLimits, setBlockedPids: traffic.setBlockedPids });
  const [showChart, setShowChart] = useState(false);
  const [chartPinned, setChartPinned] = useState(false);
  const [chartClosed, setChartClosed] = useState(false);
  const chart = useChartData(showChart, traffic.selectedPid, traffic.processes);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; process: ProcessTraffic } | null>(null);

  useEffect(() => {
    const close = () => setContextMenu(null);
    document.addEventListener("click", close);
    return () => document.removeEventListener("click", close);
  }, []);

  const handleContextMenu = useCallback((e: React.MouseEvent, process: ProcessTraffic) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, process });
  }, []);

  const chartVisible = showChart || (chartPinned && !showChart) || (!chartClosed && traffic.selectedPid !== null && traffic.liveSpeedData.length > 1);

  return (
    <main className="h-screen flex flex-col bg-ground text-fg font-display overflow-hidden">
      <Header
        totalDown={traffic.totalDown} totalUp={traffic.totalUp}
        showSettings={settings.showSettings} setShowSettings={settings.setShowSettings}
        showChart={showChart} setShowChart={setShowChart} setChartClosed={setChartClosed}
        filter={traffic.filter} setFilter={traffic.setFilter}
      />
      <div className="accent-line" />
      {settings.interceptActive && (
        <div className="flex items-center gap-2 px-4 py-1.5 bg-caution/8 border-b border-caution/15">
          <span className="w-1.5 h-1.5 rounded-full bg-caution animate-pulse-dot" />
          <span className="text-caution text-xs font-semibold tracking-wide uppercase">Intercept Active</span>
          <span className="text-caution/50 text-xs">Rate limits and blocks are enforced on live traffic</span>
        </div>
      )}
      <ProfileBar {...profiles} />
      <SettingsPanel
        showSettings={settings.showSettings} notifThreshold={settings.notifThreshold}
        setNotifThreshold={settings.setNotifThreshold} autostart={settings.autostart}
        setAutostart={settings.setAutostart} interceptActive={settings.interceptActive}
        setInterceptActive={settings.setInterceptActive} showPidColumn={traffic.showPidColumn}
        setShowPidColumn={traffic.setShowPidColumn}
      />
      <ProcessTable
        sorted={traffic.sorted} processCount={traffic.processes.length} limits={traffic.limits}
        blockedPids={traffic.blockedPids} icons={traffic.icons} showPidColumn={traffic.showPidColumn}
        editingCell={traffic.editingCell} editRef={traffic.editRef} colCount={traffic.colCount}
        maxDl={traffic.maxDl} maxUl={traffic.maxUl} selectedPid={traffic.selectedPid}
        sortIcon={traffic.sortIcon} handleSort={traffic.handleSort} setEditingCell={traffic.setEditingCell}
        applyLimit={traffic.applyLimit} toggleBlock={traffic.toggleBlock}
        setSelectedPid={traffic.setSelectedPid} handleContextMenu={handleContextMenu}
        setChartClosed={setChartClosed}
      />
      {chartVisible && (
        <ChartPanel
          showChart={showChart} chartPinned={chartPinned} setChartPinned={setChartPinned}
          setShowChart={setShowChart} setChartClosed={setChartClosed}
          chartData={chart.chartData} timeRange={chart.timeRange} setTimeRange={chart.setTimeRange}
          topConsumers={chart.topConsumers} selectedPid={traffic.selectedPid}
          processes={traffic.processes} liveSpeedData={traffic.liveSpeedData}
        />
      )}
      <ContextMenu
        contextMenu={contextMenu} limits={traffic.limits} blockedPids={traffic.blockedPids}
        setEditingCell={traffic.setEditingCell} setLimits={traffic.setLimits}
        toggleBlock={traffic.toggleBlock} setContextMenu={setContextMenu}
      />
      <StatusBar
        processCount={traffic.processes.length} shownCount={traffic.sorted.length}
        limits={traffic.limits} blockedPids={traffic.blockedPids}
        interceptActive={settings.interceptActive}
      />
    </main>
  );
}

export default App;
