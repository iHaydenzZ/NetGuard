import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";

// Mock Tauri APIs before importing the hook
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
}));

import { useTrafficData, MAX_ICON_ATTEMPTS } from "./useTrafficData";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { ProcessTrafficSnapshot } from "../bindings";

const mockedInvoke = vi.mocked(invoke);
const mockedListen = vi.mocked(listen);

const EXISTING_LIMIT = { download_bps: 500 * 1024, upload_bps: 0 };

function mockBackend() {
  mockedInvoke.mockImplementation(async (cmd: string) => {
    if (cmd === "get_traffic_stats") return [];
    if (cmd === "get_bandwidth_limits") return { 100: EXISTING_LIMIT };
    if (cmd === "get_blocked_pids") return [200];
    return undefined;
  });
}

describe("useTrafficData applyLimit", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockBackend();
  });

  it("keeps the existing limit and surfaces an error on invalid input", async () => {
    const { result } = renderHook(() => useTrafficData());
    await waitFor(() => {
      expect(result.current.limits[100]).toEqual(EXISTING_LIMIT);
    });
    mockedInvoke.mockClear();

    await act(async () => {
      await result.current.applyLimit(100, "dl", "abc");
    });

    // The typo must NOT delete the rule or reach the backend.
    expect(result.current.limits[100]).toEqual(EXISTING_LIMIT);
    expect(mockedInvoke).not.toHaveBeenCalledWith("remove_bandwidth_limit", expect.anything());
    expect(mockedInvoke).not.toHaveBeenCalledWith("set_bandwidth_limit", expect.anything());
    expect(result.current.limitInputError).not.toBeNull();
  });

  it("clears the limit on empty input", async () => {
    const { result } = renderHook(() => useTrafficData());
    await waitFor(() => {
      expect(result.current.limits[100]).toEqual(EXISTING_LIMIT);
    });

    await act(async () => {
      await result.current.applyLimit(100, "dl", "");
    });

    expect(result.current.limits[100]).toBeUndefined();
    expect(mockedInvoke).toHaveBeenCalledWith("remove_bandwidth_limit", { pid: 100 });
    expect(result.current.limitInputError).toBeNull();
  });

  it("applies a valid limit and clears any prior error", async () => {
    const { result } = renderHook(() => useTrafficData());
    await waitFor(() => {
      expect(result.current.limits[100]).toEqual(EXISTING_LIMIT);
    });

    await act(async () => {
      await result.current.applyLimit(100, "dl", "abc"); // set an error first
    });
    expect(result.current.limitInputError).not.toBeNull();

    await act(async () => {
      await result.current.applyLimit(100, "dl", "2m");
    });

    expect(result.current.limits[100]).toEqual({ download_bps: 2 * 1024 * 1024, upload_bps: 0 });
    expect(mockedInvoke).toHaveBeenCalledWith("set_bandwidth_limit", {
      pid: 100,
      downloadBps: 2 * 1024 * 1024,
      uploadBps: 0,
    });
    expect(result.current.limitInputError).toBeNull();
  });
});

describe("useTrafficData limit-path error surfacing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockBackend();
  });

  it("rejected set_bandwidth_limit keeps limits unchanged and sets controlError", async () => {
    const { result } = renderHook(() => useTrafficData());
    await waitFor(() => {
      expect(result.current.limits[100]).toEqual(EXISTING_LIMIT);
    });

    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "set_bandwidth_limit") throw { message: "Cannot control reserved system PID" };
      return undefined;
    });

    await act(async () => {
      await result.current.applyLimit(100, "dl", "2m");
    });

    expect(result.current.limits[100]).toEqual(EXISTING_LIMIT);
    expect(result.current.controlError).toBe("Cannot control reserved system PID");
  });

  it("rejected removeLimits keeps limits unchanged and sets controlError", async () => {
    const { result } = renderHook(() => useTrafficData());
    await waitFor(() => {
      expect(result.current.limits[100]).toEqual(EXISTING_LIMIT);
    });

    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "remove_bandwidth_limit") throw { message: "Cannot control reserved system PID" };
      return undefined;
    });

    await act(async () => {
      await result.current.removeLimits(100);
    });

    expect(result.current.limits[100]).toEqual(EXISTING_LIMIT);
    expect(result.current.controlError).toBe("Cannot control reserved system PID");
  });

  it("successful removeLimits clears the limit", async () => {
    const { result } = renderHook(() => useTrafficData());
    await waitFor(() => {
      expect(result.current.limits[100]).toEqual(EXISTING_LIMIT);
    });

    mockedInvoke.mockImplementation(async () => undefined);

    await act(async () => {
      await result.current.removeLimits(100);
    });

    expect(result.current.limits[100]).toBeUndefined();
  });
});

describe("useTrafficData toggleBlock", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockBackend();
  });

  it("rejected block_process leaves blockedPids unchanged and sets controlError", async () => {
    const { result } = renderHook(() => useTrafficData());
    await waitFor(() => {
      expect(result.current.blockedPids.has(200)).toBe(true);
    });

    // Simulate backend rejecting PID 4 (reserved system PID)
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "block_process") throw { message: "Cannot control reserved system PID" };
      return undefined;
    });

    await act(async () => {
      await result.current.toggleBlock(4);
    });

    // blockedPids must NOT include 4 (optimistic update must NOT have been applied)
    expect(result.current.blockedPids.has(4)).toBe(false);
    // Original blocked state must be intact
    expect(result.current.blockedPids.has(200)).toBe(true);
    // controlError must be set
    expect(result.current.controlError).toBe("Cannot control reserved system PID");
  });

  it("successful block_process adds pid to blockedPids and clears controlError", async () => {
    const { result } = renderHook(() => useTrafficData());
    await waitFor(() => {
      expect(result.current.blockedPids.has(200)).toBe(true);
    });

    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "block_process") return undefined;
      return undefined;
    });

    await act(async () => {
      await result.current.toggleBlock(300);
    });

    expect(result.current.blockedPids.has(300)).toBe(true);
    expect(result.current.controlError).toBeNull();
  });
});

// --- Icon fetching (PID-based, dedup by exe_path) ---

function makeProc(pid: number, exePath: string): ProcessTrafficSnapshot {
  return {
    pid,
    name: "app.exe",
    exe_path: exePath,
    upload_speed: 0,
    download_speed: 0,
    bytes_sent: 0,
    bytes_recv: 0,
    connection_count: 0,
  };
}

const iconCalls = () =>
  mockedInvoke.mock.calls.filter((c) => c[0] === "get_process_icon");

// Drain pending microtasks + one macrotask so invoke().then(...) callbacks
// (which mutate the iconRequested ref) run before the next snapshot is pushed.
const flush = () =>
  act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });

describe("useTrafficData icon fetching", () => {
  let trafficHandler:
    | ((event: { payload: ProcessTrafficSnapshot[] }) => void)
    | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    trafficHandler = undefined;
    // Capture the traffic-stats listener so the test can drive `processes`.
    mockedListen.mockImplementation(((event: string, cb: (e: unknown) => void) => {
      if (event === "traffic-stats") {
        trafficHandler = cb as typeof trafficHandler;
      }
      return Promise.resolve(() => {});
    }) as unknown as typeof listen);
  });

  it("retries a later process with the same exe after a transient null icon", async () => {
    // First icon request misses (process already exited); the second succeeds.
    let iconCount = 0;
    mockedInvoke.mockImplementation(async (cmd: string) => {
      switch (cmd) {
        case "get_traffic_stats":
          return [];
        case "get_bandwidth_limits":
          return {};
        case "get_blocked_pids":
          return [];
        case "get_process_icon":
          iconCount += 1;
          return iconCount === 1 ? null : "data:image/bmp;base64,AAA";
        default:
          return undefined;
      }
    });

    renderHook(() => useTrafficData());
    await flush(); // settle mount fetches (processes -> [])

    // Snapshot 1: PID 100. Backend returns null → the path must be un-marked so
    // a later process sharing the same exe can retry.
    await act(async () => {
      trafficHandler?.({ payload: [makeProc(100, "C:\\app.exe")] });
    });
    await waitFor(() => expect(iconCalls()).toHaveLength(1));
    await flush(); // let the null result clear iconRequested

    // Snapshot 2: a NEW PID 200 with the SAME exe. With the fix this retries;
    // before the fix the path stayed in iconRequested forever and never refired.
    await act(async () => {
      trafficHandler?.({ payload: [makeProc(200, "C:\\app.exe")] });
    });
    await waitFor(() => expect(iconCalls()).toHaveLength(2));
  });

  it("does not re-request an exe whose icon already loaded", async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      switch (cmd) {
        case "get_traffic_stats":
          return [];
        case "get_bandwidth_limits":
          return {};
        case "get_blocked_pids":
          return [];
        case "get_process_icon":
          return "data:image/bmp;base64,AAA";
        default:
          return undefined;
      }
    });

    renderHook(() => useTrafficData());
    await flush();

    await act(async () => {
      trafficHandler?.({ payload: [makeProc(100, "C:\\app.exe")] });
    });
    await waitFor(() => expect(iconCalls()).toHaveLength(1));
    await flush();

    // A different PID sharing the (now cached) exe must NOT trigger another call.
    await act(async () => {
      trafficHandler?.({ payload: [makeProc(200, "C:\\app.exe")] });
    });
    await flush();

    expect(iconCalls()).toHaveLength(1);
  });

  it("gives up after MAX_ICON_ATTEMPTS null results for the same exe", async () => {
    // Backend null means EITHER a transient miss OR an exe with no extractable
    // icon — it can't tell us which. A resident icon-less exe appears in every
    // snapshot, so without a cap it would be re-requested on every stats tick.
    mockedInvoke.mockImplementation(async (cmd: string) => {
      switch (cmd) {
        case "get_traffic_stats":
          return [];
        case "get_bandwidth_limits":
          return {};
        case "get_blocked_pids":
          return [];
        case "get_process_icon":
          return null;
        default:
          return undefined;
      }
    });

    renderHook(() => useTrafficData());
    await flush();

    // Each snapshot brings a fresh PID with the same exe; the first
    // MAX_ICON_ATTEMPTS are allowed to retry.
    for (let i = 1; i <= MAX_ICON_ATTEMPTS; i++) {
      await act(async () => {
        trafficHandler?.({ payload: [makeProc(100 + i, "C:\\app.exe")] });
      });
      await waitFor(() => expect(iconCalls()).toHaveLength(i));
      await flush(); // let the null result settle the retry bookkeeping
    }

    // Cap reached: yet another PID with the same exe must NOT re-request.
    await act(async () => {
      trafficHandler?.({ payload: [makeProc(999, "C:\\app.exe")] });
    });
    await flush();

    expect(iconCalls()).toHaveLength(MAX_ICON_ATTEMPTS);
  });

  it("counts rejected icon requests toward the retry cap", async () => {
    // An Err from the backend (e.g. reserved-PID rejection) repeats forever for
    // a resident process — it must hit the same cap as null results.
    mockedInvoke.mockImplementation(async (cmd: string) => {
      switch (cmd) {
        case "get_traffic_stats":
          return [];
        case "get_bandwidth_limits":
          return {};
        case "get_blocked_pids":
          return [];
        case "get_process_icon":
          throw new Error("Cannot control reserved system PID");
        default:
          return undefined;
      }
    });

    renderHook(() => useTrafficData());
    await flush();

    for (let i = 1; i <= MAX_ICON_ATTEMPTS; i++) {
      await act(async () => {
        trafficHandler?.({ payload: [makeProc(100 + i, "C:\\app.exe")] });
      });
      await waitFor(() => expect(iconCalls()).toHaveLength(i));
      await flush();
    }

    await act(async () => {
      trafficHandler?.({ payload: [makeProc(999, "C:\\app.exe")] });
    });
    await flush();

    expect(iconCalls()).toHaveLength(MAX_ICON_ATTEMPTS);
  });
});
