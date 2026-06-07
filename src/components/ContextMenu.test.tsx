import { describe, it, expect, vi } from "vitest";
import { render } from "@testing-library/react";
import { ContextMenu } from "./ContextMenu";
import type { ContextMenuProps } from "./ContextMenu";

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

function makeProps(overrides: Partial<ContextMenuProps> = {}): ContextMenuProps {
  return {
    contextMenu: { x: 10, y: 10, process: baseProcess },
    limits: {},
    blockedPids: new Set(),
    setEditingCell: vi.fn(),
    removeLimits: vi.fn(),
    toggleBlock: vi.fn(),
    setContextMenu: vi.fn(),
    interceptActive: false,
    ...overrides,
  };
}

describe("ContextMenu enforcement labels", () => {
  it("shows Queue Block and the pending hint when intercept is inactive", () => {
    const { container } = render(<ContextMenu {...makeProps({ interceptActive: false })} />);
    expect(container.textContent).toContain("Queue Block");
    expect(container.textContent).toContain("Pending until Enforce limits is active");
  });

  it("shows Block and no pending hint when intercept is active", () => {
    const { container } = render(<ContextMenu {...makeProps({ interceptActive: true })} />);
    expect(container.textContent).toContain("Block");
    expect(container.textContent).not.toContain("Queue Block");
    expect(container.textContent).not.toContain("Pending until Enforce limits is active");
  });

  it("shows Unblock for an already-blocked process regardless of intercept state", () => {
    const { container } = render(
      <ContextMenu {...makeProps({ blockedPids: new Set([100]), interceptActive: false })} />
    );
    expect(container.textContent).toContain("Unblock");
    expect(container.textContent).not.toContain("Queue Block");
  });

  it("keeps the pending hint for a blocked process when intercept is inactive (limit actions are still pending)", () => {
    const { container } = render(
      <ContextMenu {...makeProps({ blockedPids: new Set([100]), interceptActive: false })} />
    );
    expect(container.textContent).toContain("Pending until Enforce limits is active");
  });
});
