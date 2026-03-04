import { describe, it, expect, vi } from "vitest";
import { render, fireEvent } from "@testing-library/react";
import { Toggle } from "./Toggle";

describe("Toggle", () => {
  it("renders in off state with correct classes and style", () => {
    const { container } = render(<Toggle on={false} onToggle={() => {}} />);
    const button = container.querySelector("button")!;
    expect(button.className).toContain("toggle-track");
    expect(button.className).not.toContain("is-on");
    // jsdom normalizes hex colors to rgb() format
    expect(button.style.backgroundColor).toBe("rgb(61, 79, 104)");
  });

  it("renders in on state with is-on class and default neon color", () => {
    const { container } = render(<Toggle on={true} onToggle={() => {}} />);
    const button = container.querySelector("button")!;
    expect(button.className).toContain("toggle-track");
    expect(button.className).toContain("is-on");
    expect(button.style.backgroundColor).toBe("rgb(0, 216, 255)");
  });

  it("calls onToggle when clicked", () => {
    const onToggle = vi.fn();
    const { container } = render(<Toggle on={false} onToggle={onToggle} />);
    const button = container.querySelector("button")!;
    fireEvent.click(button);
    expect(onToggle).toHaveBeenCalledTimes(1);
  });

  it("applies custom color when on and color prop is provided", () => {
    const { container } = render(
      <Toggle on={true} onToggle={() => {}} color="#ff6600" />
    );
    const button = container.querySelector("button")!;
    expect(button.style.backgroundColor).toBe("rgb(255, 102, 0)");
  });

  it("ignores custom color when off", () => {
    const { container } = render(
      <Toggle on={false} onToggle={() => {}} color="#ff6600" />
    );
    const button = container.querySelector("button")!;
    expect(button.style.backgroundColor).toBe("rgb(61, 79, 104)");
  });

  it("contains a toggle-thumb span", () => {
    const { container } = render(<Toggle on={false} onToggle={() => {}} />);
    const thumb = container.querySelector(".toggle-thumb");
    expect(thumb).not.toBeNull();
    expect(thumb!.tagName).toBe("SPAN");
  });
});
