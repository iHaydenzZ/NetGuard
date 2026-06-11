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
import { listen } from "@tauri-apps/api/event";
import { act } from "@testing-library/react";

const mockedInvoke = vi.mocked(invoke);
const mockedListen = vi.mocked(listen);

describe("useSettings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedInvoke.mockResolvedValue(undefined as any);
  });

  it("initializes with default values", () => {
    // Use never-resolving promises so mount-time setState calls never fire,
    // keeping all values at their initial defaults without act() warnings.
    mockedInvoke.mockReturnValue(new Promise(() => {}));
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
    // Use never-resolving promises so no setState fires after render.
    mockedInvoke.mockReturnValue(new Promise(() => {}));
    renderHook(() => useSettings());
    expect(mockedInvoke).toHaveBeenCalledWith("get_notification_threshold");
    expect(mockedInvoke).toHaveBeenCalledWith("get_autostart");
    expect(mockedInvoke).toHaveBeenCalledWith("is_intercept_active");
  });

  it("exposes setter functions", () => {
    // Use never-resolving promises so no setState fires after render.
    mockedInvoke.mockReturnValue(new Promise(() => {}));
    const { result } = renderHook(() => useSettings());
    expect(typeof result.current.setShowSettings).toBe("function");
    expect(typeof result.current.setNotifThreshold).toBe("function");
    expect(typeof result.current.setAutostart).toBe("function");
    expect(typeof result.current.setInterceptActive).toBe("function");
  });

  it("registers a listener for the intercept-failed-open event", () => {
    // Use never-resolving promises so no setState fires after render.
    mockedInvoke.mockReturnValue(new Promise(() => {}));
    renderHook(() => useSettings());
    expect(mockedListen).toHaveBeenCalledWith(
      "intercept-failed-open",
      expect.any(Function)
    );
  });

  it("flips interceptActive to false when intercept fails open", async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "is_intercept_active") return true;
      return undefined;
    });

    // Capture the handler registered for the fail-open event.
    let failOpenHandler: ((event: unknown) => void) | undefined;
    mockedListen.mockImplementation(((eventName: string, cb: (event: unknown) => void) => {
      if (eventName === "intercept-failed-open") failOpenHandler = cb;
      return Promise.resolve(() => {});
    }) as unknown as typeof listen);

    const { result } = renderHook(() => useSettings());

    await waitFor(() => {
      expect(result.current.interceptActive).toBe(true);
    });

    act(() => {
      failOpenHandler?.({ payload: null });
    });

    expect(result.current.interceptActive).toBe(false);
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
