import { describe, it, expect, vi } from "vitest";
import { render } from "@testing-library/react";
import { ProcessTable } from "./ProcessTable";
import type { ProcessTableProps } from "./ProcessTable";
import { createRef } from "react";

const PENDING_TITLE = "Pending — enable Enforce limits in Settings to activate";

const baseProcess = {
  pid: 100,
  name: "chrome.exe",
  exe_path: "C:\\Program Files\\Google\\Chrome\\chrome.exe",
  upload_speed: 0,
  download_speed: 0,
  bytes_sent: 0,
  bytes_recv: 0,
  connection_count: 2,
};

function makeProps(overrides: Partial<ProcessTableProps> = {}): ProcessTableProps {
  return {
    sorted: [baseProcess],
    processCount: 1,
    limits: {},
    blockedPids: new Set(),
    icons: {},
    showPidColumn: false,
    editingCell: null,
    editRef: createRef<HTMLInputElement>(),
    colCount: 9,
    maxDl: 0,
    maxUl: 0,
    selectedPid: null,
    sortIcon: () => "",
    handleSort: vi.fn(),
    setEditingCell: vi.fn(),
    applyLimit: vi.fn(),
    toggleBlock: vi.fn(),
    setSelectedPid: vi.fn(),
    handleContextMenu: vi.fn(),
    setChartClosed: vi.fn(),
    interceptActive: false,
    ...overrides,
  };
}

describe("ProcessTable pending indication", () => {
  it("shows Pending badge when process has limit and intercept is inactive", () => {
    const props = makeProps({
      limits: { 100: { download_bps: 1024, upload_bps: 0 } },
      interceptActive: false,
    });
    const { container } = render(<ProcessTable {...props} />);
    const pendingBadge = container.querySelector(`[title='${PENDING_TITLE}']`);
    expect(pendingBadge).not.toBeNull();
    expect(pendingBadge!.textContent).toBe("Pending");
  });

  it("does not show Pending badge when process has limit and intercept is active", () => {
    const props = makeProps({
      limits: { 100: { download_bps: 1024, upload_bps: 0 } },
      interceptActive: true,
    });
    const { container } = render(<ProcessTable {...props} />);
    const pendingBadge = container.querySelector(`[title='${PENDING_TITLE}']`);
    expect(pendingBadge).toBeNull();
  });

  it("shows Pending badge when process is blocked and intercept is inactive", () => {
    const props = makeProps({
      blockedPids: new Set([100]),
      interceptActive: false,
    });
    const { container } = render(<ProcessTable {...props} />);
    const pendingBadge = container.querySelector(`[title='${PENDING_TITLE}']`);
    expect(pendingBadge).not.toBeNull();
    expect(pendingBadge!.textContent).toBe("Pending");
  });

  it("does not show Pending badge when process is blocked and intercept is active", () => {
    const props = makeProps({
      blockedPids: new Set([100]),
      interceptActive: true,
    });
    const { container } = render(<ProcessTable {...props} />);
    const pendingBadge = container.querySelector(`[title='${PENDING_TITLE}']`);
    expect(pendingBadge).toBeNull();
  });

  it("does not show Pending badge for unrestricted process regardless of intercept state", () => {
    const props = makeProps({
      limits: {},
      blockedPids: new Set(),
      interceptActive: false,
    });
    const { container } = render(<ProcessTable {...props} />);
    const pendingBadge = container.querySelector(`[title='${PENDING_TITLE}']`);
    expect(pendingBadge).toBeNull();
  });

  it("renders process name", () => {
    const props = makeProps();
    const { container } = render(<ProcessTable {...props} />);
    expect(container.textContent).toContain("chrome.exe");
  });
});
