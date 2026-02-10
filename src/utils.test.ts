import { describe, it, expect } from "vitest";
import { formatSpeed, formatBytes, parseLimitInput, timeRangeSeconds } from "./utils";
import type { TimeRange } from "./utils";

describe("formatSpeed", () => {
  it("formats 0 B/s", () => {
    expect(formatSpeed(0)).toBe("0 B/s");
  });

  it("formats sub-KB values in B/s", () => {
    expect(formatSpeed(1)).toBe("1 B/s");
    expect(formatSpeed(512)).toBe("512 B/s");
    expect(formatSpeed(1023)).toBe("1023 B/s");
  });

  it("formats KB range values", () => {
    expect(formatSpeed(1024)).toBe("1.0 KB/s");
    expect(formatSpeed(1536)).toBe("1.5 KB/s");
    expect(formatSpeed(10240)).toBe("10.0 KB/s");
    expect(formatSpeed(500 * 1024)).toBe("500.0 KB/s");
  });

  it("formats MB range values", () => {
    expect(formatSpeed(1024 * 1024)).toBe("1.00 MB/s");
    expect(formatSpeed(1.5 * 1024 * 1024)).toBe("1.50 MB/s");
    expect(formatSpeed(10 * 1024 * 1024)).toBe("10.00 MB/s");
    expect(formatSpeed(100 * 1024 * 1024)).toBe("100.00 MB/s");
  });

  it("handles the exact boundary between B/s and KB/s", () => {
    expect(formatSpeed(1023)).toBe("1023 B/s");
    expect(formatSpeed(1024)).toBe("1.0 KB/s");
  });

  it("handles the exact boundary between KB/s and MB/s", () => {
    expect(formatSpeed(1024 * 1024 - 1)).toMatch(/KB\/s$/);
    expect(formatSpeed(1024 * 1024)).toBe("1.00 MB/s");
  });

  it("handles fractional bytes per second", () => {
    expect(formatSpeed(0.4)).toBe("0 B/s");
    expect(formatSpeed(0.6)).toBe("1 B/s");
  });
});

describe("formatBytes", () => {
  it("formats 0 B", () => {
    expect(formatBytes(0)).toBe("0 B");
  });

  it("formats byte-range values", () => {
    expect(formatBytes(1)).toBe("1 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1023)).toBe("1023 B");
  });

  it("formats KB range values", () => {
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(10 * 1024)).toBe("10.0 KB");
  });

  it("formats MB range values", () => {
    expect(formatBytes(1024 * 1024)).toBe("1.0 MB");
    expect(formatBytes(5.5 * 1024 * 1024)).toBe("5.5 MB");
    expect(formatBytes(100 * 1024 * 1024)).toBe("100.0 MB");
  });

  it("formats GB range values", () => {
    expect(formatBytes(1024 * 1024 * 1024)).toBe("1.00 GB");
    expect(formatBytes(2.5 * 1024 * 1024 * 1024)).toBe("2.50 GB");
    expect(formatBytes(10 * 1024 * 1024 * 1024)).toBe("10.00 GB");
  });

  it("handles boundaries correctly", () => {
    expect(formatBytes(1023)).toBe("1023 B");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1024 * 1024 - 1)).toMatch(/KB$/);
    expect(formatBytes(1024 * 1024)).toBe("1.0 MB");
    expect(formatBytes(1024 * 1024 * 1024 - 1)).toMatch(/MB$/);
    expect(formatBytes(1024 * 1024 * 1024)).toBe("1.00 GB");
  });
});

describe("parseLimitInput", () => {
  it("parses plain number as KB", () => {
    expect(parseLimitInput("500")).toBe(500 * 1024);
    expect(parseLimitInput("1")).toBe(1024);
    expect(parseLimitInput("100")).toBe(100 * 1024);
  });

  it("parses 'k' suffix as KB", () => {
    expect(parseLimitInput("500k")).toBe(500 * 1024);
    expect(parseLimitInput("10k")).toBe(10 * 1024);
  });

  it("parses 'kb' suffix as KB", () => {
    expect(parseLimitInput("100kb")).toBe(100 * 1024);
    expect(parseLimitInput("256kb")).toBe(256 * 1024);
  });

  it("parses 'm' suffix as MB", () => {
    expect(parseLimitInput("5m")).toBe(5 * 1024 * 1024);
    expect(parseLimitInput("1m")).toBe(1024 * 1024);
  });

  it("parses 'mb' suffix as MB", () => {
    expect(parseLimitInput("1.5mb")).toBe(Math.round(1.5 * 1024 * 1024));
    expect(parseLimitInput("10mb")).toBe(10 * 1024 * 1024);
  });

  it("is case-insensitive", () => {
    expect(parseLimitInput("5M")).toBe(5 * 1024 * 1024);
    expect(parseLimitInput("100KB")).toBe(100 * 1024);
    expect(parseLimitInput("2MB")).toBe(2 * 1024 * 1024);
  });

  it("handles whitespace around input", () => {
    expect(parseLimitInput("  500  ")).toBe(500 * 1024);
    expect(parseLimitInput("  5m  ")).toBe(5 * 1024 * 1024);
  });

  it("handles whitespace between number and unit", () => {
    expect(parseLimitInput("500 k")).toBe(500 * 1024);
    expect(parseLimitInput("5 m")).toBe(5 * 1024 * 1024);
  });

  it("returns null for empty string", () => {
    expect(parseLimitInput("")).toBeNull();
    expect(parseLimitInput("   ")).toBeNull();
  });

  it("returns null for invalid input", () => {
    expect(parseLimitInput("abc")).toBeNull();
    expect(parseLimitInput("hello world")).toBeNull();
    expect(parseLimitInput("12.34.56")).toBeNull();
    expect(parseLimitInput("--5")).toBeNull();
  });

  it("parses '0' as 0 KB (which rounds to 0)", () => {
    expect(parseLimitInput("0")).toBe(0);
  });

  it("handles decimal values", () => {
    expect(parseLimitInput("1.5")).toBe(Math.round(1.5 * 1024));
    expect(parseLimitInput("0.5m")).toBe(Math.round(0.5 * 1024 * 1024));
  });
});

describe("timeRangeSeconds", () => {
  it("returns 3600 for '1h'", () => {
    expect(timeRangeSeconds("1h")).toBe(3600);
  });

  it("returns 86400 for '24h'", () => {
    expect(timeRangeSeconds("24h")).toBe(86400);
  });

  it("returns 604800 for '7d'", () => {
    expect(timeRangeSeconds("7d")).toBe(604800);
  });

  it("returns 2592000 for '30d'", () => {
    expect(timeRangeSeconds("30d")).toBe(2592000);
  });

  it("covers all TimeRange values", () => {
    const ranges: TimeRange[] = ["1h", "24h", "7d", "30d"];
    for (const range of ranges) {
      expect(typeof timeRangeSeconds(range)).toBe("number");
      expect(timeRangeSeconds(range)).toBeGreaterThan(0);
    }
  });

  it("returns progressively larger values", () => {
    expect(timeRangeSeconds("1h")).toBeLessThan(timeRangeSeconds("24h"));
    expect(timeRangeSeconds("24h")).toBeLessThan(timeRangeSeconds("7d"));
    expect(timeRangeSeconds("7d")).toBeLessThan(timeRangeSeconds("30d"));
  });
});
