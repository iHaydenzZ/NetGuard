import { vi } from "vitest";

const noop = () => {};
export const listen = vi.fn().mockResolvedValue(noop);
export const emit = vi.fn().mockResolvedValue(undefined);
