import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { formatSpeed } from "../utils";

export function useSettings() {
  const [showSettings, setShowSettings] = useState(false);
  const [notifThreshold, setNotifThreshold] = useState(0);
  const [autostart, setAutostart] = useState(false);
  const [interceptActive, setInterceptActive] = useState(false);

  // Initial settings fetch
  useEffect(() => {
    invoke<number>("get_notification_threshold").then(setNotifThreshold).catch(() => {});
    invoke<boolean>("get_autostart").then(setAutostart).catch(() => {});
    invoke<boolean>("is_intercept_active").then(setInterceptActive).catch(() => {});
  }, []);

  // Threshold-exceeded notification listener
  useEffect(() => {
    const unlisten = listen<{ pid: number; name: string; speed: number; threshold: number }>(
      "threshold-exceeded",
      (event) => {
        const { name, speed } = event.payload;
        if ("Notification" in window && Notification.permission === "granted") {
          new Notification("NetGuard: Bandwidth Alert", { body: `${name} is using ${formatSpeed(speed)}` });
        } else if ("Notification" in window && Notification.permission !== "denied") {
          Notification.requestPermission().then((perm) => {
            if (perm === "granted") {
              new Notification("NetGuard: Bandwidth Alert", { body: `${name} is using ${formatSpeed(speed)}` });
            }
          });
        }
      }
    );
    return () => { unlisten.then((fn) => fn()); };
  }, []);

  return {
    showSettings,
    setShowSettings,
    notifThreshold,
    setNotifThreshold,
    autostart,
    setAutostart,
    interceptActive,
    setInterceptActive,
  };
}
