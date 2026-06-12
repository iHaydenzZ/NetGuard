export type TimeRange = "1h" | "24h" | "7d" | "30d";

export function formatSpeed(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`;
  if (bytesPerSec < 1024 * 1024)
    return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSec / (1024 * 1024)).toFixed(2)} MB/s`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export type BandwidthInput =
  | { kind: "empty" }
  | { kind: "invalid" }
  | { kind: "value"; bps: number };

export function parseBandwidthInput(input: string): BandwidthInput {
  const trimmed = input.trim().toLowerCase();
  if (!trimmed) return { kind: "empty" };
  const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(k|m|kb|mb)?$/);
  if (!match) return { kind: "invalid" };
  const value = parseFloat(match[1]);
  const unit = match[2] || "k";
  const bps = unit.startsWith("m")
    ? Math.round(value * 1024 * 1024)
    : Math.round(value * 1024);
  return { kind: "value", bps };
}

/** @deprecated Use parseBandwidthInput instead. Returns null for both empty and invalid. */
export function parseLimitInput(input: string): number | null {
  const parsed = parseBandwidthInput(input);
  return parsed.kind === "value" ? parsed.bps : null;
}

/** Returns true if text contains any non-ASCII characters (Unicode spoofing indicator). */
export function hasNonAscii(text: string): boolean {
  return /[^\x00-\x7F]/.test(text);
}

/** Sanitize an attacker-influenced process name for OS notification text:
 *  any local process picks its own name, so strip control/non-ASCII chars
 *  (Unicode spoofing) and truncate. React-rendered contexts are escaped
 *  already; this is for sinks outside the DOM (Notification body). */
export function sanitizeProcessName(name: string, maxLength = 64): string {
  const cleaned = name.replace(/[^\x20-\x7E]/g, "?");
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength)}…` : cleaned;
}

/** Validate a profile name. Returns an error message string, or null if valid. */
export function validateProfileName(name: string): string | null {
  const trimmed = name.trim();
  if (!trimmed) return "Profile name must not be empty";
  if (trimmed.length > 64) return "Profile name must be 64 characters or fewer";
  if (!/^[A-Za-z0-9 _-]+$/.test(trimmed)) return "Only letters, numbers, spaces, hyphens, and underscores allowed";
  return null;
}

export function timeRangeSeconds(range: TimeRange): number {
  switch (range) {
    case "1h": return 3600;
    case "24h": return 86400;
    case "7d": return 604800;
    case "30d": return 2592000;
  }
}
