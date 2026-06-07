import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";

// Mock Tauri APIs before importing the hook
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
}));

import { useTrafficData } from "./useTrafficData";
import { invoke } from "@tauri-apps/api/core";

const mockedInvoke = vi.mocked(invoke);

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
