import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent, waitFor } from "@testing-library/react";

// Mock Tauri APIs before importing the component
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { SettingsPanel } from "./SettingsPanel";
import { invoke } from "@tauri-apps/api/core";

const mockedInvoke = vi.mocked(invoke);

function renderPanel(overrides: { interceptActive?: boolean; setInterceptActive?: (v: boolean) => void } = {}) {
  const setInterceptActive = overrides.setInterceptActive ?? vi.fn();
  const utils = render(
    <SettingsPanel
      showSettings={true}
      notifThreshold={0}
      setNotifThreshold={vi.fn()}
      autostart={false}
      setAutostart={vi.fn()}
      interceptActive={overrides.interceptActive ?? false}
      setInterceptActive={setInterceptActive}
      showPidColumn={false}
      setShowPidColumn={vi.fn()}
    />
  );
  return { ...utils, setInterceptActive };
}

/** The Enforce limits toggle is the last toggle button in the panel. */
function enforceToggle(container: HTMLElement): HTMLElement {
  const buttons = container.querySelectorAll("button");
  return buttons[buttons.length - 1] as HTMLElement;
}

describe("SettingsPanel intercept toggle", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("reconciles with backend state instead of assuming enable means active", async () => {
    // The intercept loop died instantly: the backend failed open (back to
    // SNIFF) and emitted intercept-failed-open while enable_intercept_mode
    // was still resolving. Blindly setting true here would overwrite the
    // fail-open event and the toggle would lie.
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "enable_intercept_mode") return undefined;
      if (cmd === "is_intercept_active") return false;
      return undefined;
    });

    const { container, setInterceptActive } = renderPanel();
    fireEvent.click(enforceToggle(container));

    await waitFor(() => expect(setInterceptActive).toHaveBeenCalledWith(false));
    expect(setInterceptActive).not.toHaveBeenCalledWith(true);
  });

  it("shows active when the backend confirms intercept is running", async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "enable_intercept_mode") return undefined;
      if (cmd === "is_intercept_active") return true;
      return undefined;
    });

    const { container, setInterceptActive } = renderPanel();
    fireEvent.click(enforceToggle(container));

    await waitFor(() => expect(setInterceptActive).toHaveBeenCalledWith(true));
  });

  it("disables without consulting is_intercept_active", async () => {
    mockedInvoke.mockImplementation(async () => undefined);

    const { container, setInterceptActive } = renderPanel({ interceptActive: true });
    fireEvent.click(enforceToggle(container));

    await waitFor(() => expect(setInterceptActive).toHaveBeenCalledWith(false));
    expect(mockedInvoke).toHaveBeenCalledWith("disable_intercept_mode");
    expect(mockedInvoke).not.toHaveBeenCalledWith("is_intercept_active");
  });
});
