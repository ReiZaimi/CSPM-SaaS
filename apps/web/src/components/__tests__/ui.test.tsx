import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBadge as Badge } from "../security/SeverityBadge";
import { StatusPill } from "../security/StatusPill";
import { SecurityScore } from "../security/SecurityScore";
import { ContextRow } from "../security/ContextProvenance";

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

describe("SeverityBadge", () => {
  it("marks UNKNOWN with more than a colour", () => {
    // Someone who cannot separate the hues still has to be able to tell "we
    // could not look" from "we looked and it was fine". That distinction is the
    // product's whole claim to honesty, and colour alone would hide it.
    const { container } = render(<Badge level="UNKNOWN" />);
    expect(container.querySelector("svg")).toBeInTheDocument();
  });

  it("does not mark a severity that was actually determined", () => {
    const { container } = render(<Badge level="CRITICAL" />);
    expect(container.querySelector("svg")).not.toBeInTheDocument();
  });
});

describe("SecurityScore", () => {
  it("gives the number a scale and a meaning", () => {
    // "82" alone invites two questions -- out of what, and is that good.
    render(<SecurityScore score={82} delta={null} />);
    expect(screen.getByText("82")).toBeInTheDocument();
    expect(screen.getByText("/ 100")).toBeInTheDocument();
    expect(screen.getByText("Needs attention")).toBeInTheDocument();
  });

  it("does not claim a trend it cannot measure", () => {
    render(<SecurityScore score={70} delta={null} />);
    expect(screen.getByText(/no previous scan/i)).toBeInTheDocument();
  });

  it("exposes the proportion to assistive technology", () => {
    render(<SecurityScore score={41} delta={null} />);
    expect(screen.getByRole("meter", { name: /security score/i })).toHaveAttribute(
      "aria-valuenow",
      "41",
    );
  });
});

describe("ContextRow", () => {
  it("distinguishes a value somebody chose from one CloudGuard guessed", () => {
    // The three context values multiply a finding into a risk. "CRITICAL"
    // invites the question "says who", and until the backend recorded
    // provenance there was no answer to give.
    const { container: declared } = render(
      <ContextRow
        label="Criticality"
        fact={{ value: "CRITICAL", source: "customer", confidence: 1 }}
      />,
    );
    const { container: guessed } = render(
      <ContextRow
        label="Criticality"
        fact={{ value: "CRITICAL", source: "inferred", confidence: 0.4 }}
      />,
    );
    expect(declared.innerHTML).not.toBe(guessed.innerHTML);
  });

  it("falls back without provenance rather than claiming a source", () => {
    render(<ContextRow label="Criticality" fallback={<Badge level="HIGH" />} />);
    expect(screen.getByText("High")).toBeInTheDocument();
  });
});
