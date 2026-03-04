import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import { Badge } from "./Badge";

describe("Badge", () => {
  it("renders children text", () => {
    const { container } = render(<Badge color="neon">Active</Badge>);
    expect(container.textContent).toBe("Active");
  });

  it("renders as a span element", () => {
    const { container } = render(<Badge color="neon">Test</Badge>);
    const span = container.querySelector("span");
    expect(span).not.toBeNull();
  });

  it("applies caution color classes", () => {
    const { container } = render(<Badge color="caution">Warning</Badge>);
    const span = container.querySelector("span")!;
    expect(span.className).toContain("bg-caution/10");
    expect(span.className).toContain("text-caution");
    expect(span.className).toContain("border-caution/20");
  });

  it("applies danger color classes", () => {
    const { container } = render(<Badge color="danger">Error</Badge>);
    const span = container.querySelector("span")!;
    expect(span.className).toContain("bg-danger/10");
    expect(span.className).toContain("text-danger");
    expect(span.className).toContain("border-danger/20");
  });

  it("applies neon color classes", () => {
    const { container } = render(<Badge color="neon">Online</Badge>);
    const span = container.querySelector("span")!;
    expect(span.className).toContain("bg-neon/10");
    expect(span.className).toContain("text-neon");
    expect(span.className).toContain("border-neon/20");
  });

  it("applies iris color classes", () => {
    const { container } = render(<Badge color="iris">Info</Badge>);
    const span = container.querySelector("span")!;
    expect(span.className).toContain("bg-iris/10");
    expect(span.className).toContain("text-iris");
    expect(span.className).toContain("border-iris/20");
  });

  it("includes common styling classes", () => {
    const { container } = render(<Badge color="neon">Test</Badge>);
    const span = container.querySelector("span")!;
    expect(span.className).toContain("inline-flex");
    expect(span.className).toContain("rounded-full");
    expect(span.className).toContain("border");
    expect(span.className).toContain("font-semibold");
  });
});
