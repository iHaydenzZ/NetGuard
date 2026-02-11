import { invoke } from "@tauri-apps/api/core";
import { formatSpeed, parseLimitInput } from "../utils";
import { Toggle } from "./ui/Toggle";
import { SettingToggle } from "./ui/SettingToggle";

export interface SettingsPanelProps {
  showSettings: boolean;
  notifThreshold: number;
  setNotifThreshold: (v: number) => void;
  autostart: boolean;
  setAutostart: (v: boolean) => void;
  interceptActive: boolean;
  setInterceptActive: (v: boolean) => void;
  showPidColumn: boolean;
  setShowPidColumn: (v: boolean) => void;
}

export function SettingsPanel({
  showSettings,
  notifThreshold,
  setNotifThreshold,
  autostart,
  setAutostart,
  interceptActive,
  setInterceptActive,
  showPidColumn,
  setShowPidColumn,
}: SettingsPanelProps) {
  if (!showSettings) return null;

  const handleThreshold = (value: string) => {
    const bps = parseLimitInput(value);
    const val = bps ?? 0;
    setNotifThreshold(val);
    invoke("set_notification_threshold", { thresholdBps: val });
  };

  return (
    <div className="animate-slide-down border-b border-subtle/50">
      <div className="mx-3 my-2 p-3 bg-raised/80 rounded-lg border border-subtle">
        <div className="flex items-center gap-8 text-xs flex-wrap">
          {/* Bandwidth threshold */}
          <div className="flex items-center gap-2">
            <span className="text-dim">Alert threshold</span>
            <input
              type="text"
              defaultValue={notifThreshold > 0 ? (notifThreshold >= 1024 * 1024 ? `${(notifThreshold / (1024 * 1024)).toFixed(1)}m` : `${Math.round(notifThreshold / 1024)}`) : ""}
              placeholder="e.g. 500 or 5m"
              className="px-2 py-1 text-xs rounded-md bg-overlay border border-subtle text-fg focus:outline-none focus:border-neon/50 w-24 font-mono"
              onKeyDown={(e) => {
                if (e.key === "Enter") handleThreshold(e.currentTarget.value);
              }}
              onBlur={(e) => handleThreshold(e.currentTarget.value)}
            />
            <span className="text-faint">{notifThreshold > 0 ? formatSpeed(notifThreshold) : "off"}</span>
          </div>

          <div className="h-4 w-px bg-subtle" />

          {/* Show PID */}
          <SettingToggle label="Show PID" on={showPidColumn} onToggle={() => setShowPidColumn(!showPidColumn)} color="#00d8ff" />

          <div className="h-4 w-px bg-subtle" />

          {/* Autostart */}
          <SettingToggle
            label="Start on login"
            on={autostart}
            onToggle={async () => {
              const next = !autostart;
              await invoke("set_autostart", { enabled: next }).catch(() => {});
              setAutostart(next);
            }}
            color="#00d8ff"
          />

          <div className="h-4 w-px bg-subtle" />

          {/* Enforce limits */}
          <div className="flex items-center gap-2">
            <span className={interceptActive ? "text-caution font-medium" : "text-dim"}>Enforce limits</span>
            <Toggle
              on={interceptActive}
              color={interceptActive ? "#ffb020" : undefined}
              onToggle={async () => {
                try {
                  if (interceptActive) {
                    await invoke("disable_intercept_mode");
                    setInterceptActive(false);
                  } else {
                    await invoke("enable_intercept_mode", { filter: null });
                    setInterceptActive(true);
                  }
                } catch (e) {
                  console.error("Intercept toggle failed:", e);
                }
              }}
            />
            {interceptActive && <span className="text-caution text-[10px] font-semibold uppercase tracking-wider">Active</span>}
          </div>
        </div>
      </div>
    </div>
  );
}
