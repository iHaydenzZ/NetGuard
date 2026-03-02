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

export function parseLimitInput(input: string): number | null {
  const trimmed = input.trim().toLowerCase();
  if (!trimmed) return null;
  const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(k|m|kb|mb)?$/);
  if (!match) return null;
  const value = parseFloat(match[1]);
  const unit = match[2] || "k";
  if (unit.startsWith("m")) return Math.round(value * 1024 * 1024);
  return Math.round(value * 1024);
}

/** Returns true if text contains any non-ASCII characters (Unicode spoofing indicator). */
export function hasNonAscii(text: string): boolean {
  return /[^\x00-\x7F]/.test(text);
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
