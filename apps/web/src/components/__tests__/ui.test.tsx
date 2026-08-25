import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Badge, StatusPill } from "../ui";

describe("Badge", () => {
  it("labels a level when no children are given", () => {
    render(<Badge level="CRITICAL" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("marks UNKNOWN visually distinctly from LOW", () => {
    const { container: unknown } = render(<Badge level="UNKNOWN" />);
    const { container: low } = render(<Badge level="LOW" />);
    expect(unknown.firstElementChild?.className).not.toBe(low.firstElementChild?.className);
  });
});

describe("StatusPill", () => {
  it("presents a verified fix as a success state", () => {
    const { container } = render(<StatusPill status="RESOLVED" />);
    expect(screen.getByText("Verified fixed")).toBeInTheDocument();
    expect(container.firstElementChild?.className).toContain("text-ok");
  });

  it("presents a partial scan as a caution, not a success", () => {
    const { container } = render(<StatusPill status="PARTIAL" />);
    expect(container.firstElementChild?.className).toContain("text-medium");
  });

  it("does not present an accepted risk as resolved", () => {
    const { container } = render(<StatusPill status="ACCEPTED_RISK" />);
    expect(container.firstElementChild?.className).not.toContain("text-ok");
  });
});
