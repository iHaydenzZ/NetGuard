import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const read = (rel: string) =>
  readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf-8");

// Regression guards for the self-hosted-fonts hardening (June 2026 security
// review): the CSP was tightened to self-only once before (f13a8e7) and then
// reverted (2851387). These tests make the next revert fail CI.
describe("content security policy", () => {
  it("allows no external https origins", () => {
    const conf = JSON.parse(read("../src-tauri/tauri.conf.json"));
    const csp: string = conf.app.security.csp;
    expect(csp).not.toContain("googleapis");
    expect(csp).not.toContain("gstatic");
    expect(csp).not.toMatch(/https:\/\//);
  });
});

describe("index.html", () => {
  it("references no remote resources", () => {
    expect(read("../index.html")).not.toContain("https://");
  });
});
