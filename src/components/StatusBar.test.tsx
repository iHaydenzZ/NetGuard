import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import { StatusBar } from "./StatusBar";

describe("StatusBar", () => {
  it("shows limited count when intercept is active", () => {
    const { container } = render(
      <StatusBar
        processCount={3}
        shownCount={3}
        limits={{ 100: { download_bps: 1024, upload_bps: 0 } }}
        blockedPids={new Set()}
        interceptActive={true}
      />
    );
    expect(container.textContent).toContain("1 limited");
    expect(container.textContent).not.toContain("pending");
  });

  it("labels limits as pending when intercept is inactive", () => {
    const { container } = render(
      <StatusBar
        processCount={3}
        shownCount={3}
        limits={{ 100: { download_bps: 1024, upload_bps: 0 } }}
        blockedPids={new Set()}
        interceptActive={false}
      />
    );
    expect(container.textContent).toContain("1 pending limit");
    expect(container.textContent).not.toContain("1 limited");
  });

  it("shows blocked count when intercept is active", () => {
    const { container } = render(
      <StatusBar
        processCount={3}
        shownCount={3}
        limits={{}}
        blockedPids={new Set([200])}
        interceptActive={true}
      />
    );
    expect(container.textContent).toContain("1 blocked");
    expect(container.textContent).not.toContain("pending");
  });

  it("labels blocks as pending when intercept is inactive", () => {
    const { container } = render(
      <StatusBar
        processCount={3}
        shownCount={3}
        limits={{}}
        blockedPids={new Set([200])}
        interceptActive={false}
      />
    );
    expect(container.textContent).toContain("1 pending block");
    expect(container.textContent).not.toContain("1 blocked");
  });

  it("pluralizes multiple pending limits correctly", () => {
    const { container } = render(
      <StatusBar
        processCount={5}
        shownCount={5}
        limits={{
          100: { download_bps: 1024, upload_bps: 0 },
          200: { download_bps: 2048, upload_bps: 0 },
        }}
        blockedPids={new Set()}
        interceptActive={false}
      />
    );
    expect(container.textContent).toContain("2 pending limits");
  });

  it("pluralizes multiple pending blocks correctly", () => {
    const { container } = render(
      <StatusBar
        processCount={5}
        shownCount={5}
        limits={{}}
        blockedPids={new Set([100, 200])}
        interceptActive={false}
      />
    );
    expect(container.textContent).toContain("2 pending blocks");
  });

  it("shows process count", () => {
    const { container } = render(
      <StatusBar
        processCount={7}
        shownCount={7}
        limits={{}}
        blockedPids={new Set()}
        interceptActive={false}
      />
    );
    expect(container.textContent).toContain("7 processes");
  });

  it("shows shown count when different from process count", () => {
    const { container } = render(
      <StatusBar
        processCount={10}
        shownCount={4}
        limits={{}}
        blockedPids={new Set()}
        interceptActive={false}
      />
    );
    expect(container.textContent).toContain("4 shown");
  });
});
