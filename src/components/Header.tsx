import { formatSpeed } from "../utils";

interface HeaderProps {
  totalDown: number;
  totalUp: number;
  showSettings: boolean;
  setShowSettings: (fn: (v: boolean) => boolean) => void;
  showChart: boolean;
  setShowChart: (fn: (v: boolean) => boolean) => void;
  setChartClosed: (v: boolean) => void;
  filter: string;
  setFilter: (v: string) => void;
}

export function Header({ totalDown, totalUp, showSettings, setShowSettings, showChart, setShowChart, setChartClosed, filter, setFilter }: HeaderProps) {
  return (
    <header className="flex items-center gap-4 px-4 py-2.5 bg-panel">
      <div className="flex items-center gap-2.5">
        <h1 className="text-lg font-bold tracking-tight">
          <span className="text-neon">Net</span><span className="text-fg">Guard</span>
        </h1>
        {(totalDown + totalUp > 0) && (
          <span className="w-1.5 h-1.5 rounded-full bg-dl animate-pulse-dot" />
        )}
      </div>

      <div className="h-4 w-px bg-subtle mx-1" />

      <div className="flex items-center gap-4 font-mono text-sm">
        <span className="text-dl flex items-center gap-1.5">
          <svg width="10" height="10" viewBox="0 0 10 10" className="opacity-60"><path d="M5 2 L5 8 M2 5 L5 8 L8 5" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round"/></svg>
          {formatSpeed(totalDown)}
        </span>
        <span className="text-ul flex items-center gap-1.5">
          <svg width="10" height="10" viewBox="0 0 10 10" className="opacity-60"><path d="M5 8 L5 2 M2 5 L5 2 L8 5" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round"/></svg>
          {formatSpeed(totalUp)}
        </span>
      </div>

      <div className="flex-1" />

      <button
        onClick={() => setShowSettings((v) => !v)}
        className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all duration-150 ${
          showSettings
            ? "bg-neon/15 text-neon border border-neon/30"
            : "bg-raised text-dim border border-subtle hover:text-fg hover:border-muted"
        }`}
      >
        Settings
      </button>
      <button
        onClick={() => { setShowChart((v) => !v); setChartClosed(false); }}
        className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all duration-150 ${
          showChart
            ? "bg-iris/15 text-iris border border-iris/30"
            : "bg-raised text-dim border border-subtle hover:text-fg hover:border-muted"
        }`}
      >
        History
      </button>

      <div className="relative">
        <input
          type="text"
          placeholder={"Filter processes\u2026"}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="pl-8 pr-3 py-1.5 text-sm rounded-md bg-raised border border-subtle text-fg placeholder-faint focus:outline-none focus:border-neon/50 focus:bg-overlay w-52 transition-colors"
        />
        <svg className="absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      </div>
    </header>
  );
}
