import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

// Mock Tauri APIs before importing the hook
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
}));

import { useSettings } from "./useSettings";
import { invoke } from "@tauri-apps/api/core";

const mockedInvoke = vi.mocked(invoke);

describe("useSettings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedInvoke.mockResolvedValue(undefined as any);
  });

  it("initializes with default values", () => {
    const { result } = renderHook(() => useSettings());
    expect(result.current.showSettings).toBe(false);
    expect(result.current.notifThreshold).toBe(0);
    expect(result.current.autostart).toBe(false);
    expect(result.current.interceptActive).toBe(false);
  });

  it("fetches initial settings on mount", async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "get_notification_threshold") return 1024;
      if (cmd === "get_autostart") return true;
      if (cmd === "is_intercept_active") return false;
      return undefined;
    });

    const { result } = renderHook(() => useSettings());

    await waitFor(() => {
      expect(result.current.notifThreshold).toBe(1024);
    });
    expect(result.current.autostart).toBe(true);
    expect(result.current.interceptActive).toBe(false);
  });

  it("invokes all three setting commands on mount", () => {
    renderHook(() => useSettings());
    expect(mockedInvoke).toHaveBeenCalledWith("get_notification_threshold");
    expect(mockedInvoke).toHaveBeenCalledWith("get_autostart");
    expect(mockedInvoke).toHaveBeenCalledWith("is_intercept_active");
  });

  it("exposes setter functions", () => {
    const { result } = renderHook(() => useSettings());
    expect(typeof result.current.setShowSettings).toBe("function");
    expect(typeof result.current.setNotifThreshold).toBe("function");
    expect(typeof result.current.setAutostart).toBe("function");
    expect(typeof result.current.setInterceptActive).toBe("function");
  });

  it("handles rejected invoke calls gracefully", async () => {
    mockedInvoke.mockRejectedValue(new Error("command not found"));

    const { result } = renderHook(() => useSettings());

    // Wait a tick for all promises to settle
    await waitFor(() => {
      expect(mockedInvoke).toHaveBeenCalledTimes(3);
    });

    // Defaults should remain since all invocations failed
    expect(result.current.notifThreshold).toBe(0);
    expect(result.current.autostart).toBe(false);
    expect(result.current.interceptActive).toBe(false);
  });
});
