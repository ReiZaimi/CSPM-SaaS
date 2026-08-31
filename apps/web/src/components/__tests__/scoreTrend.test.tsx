/**
 * The score trend.
 *
 * A delta says something moved. The line says whether that is a trend or a
 * wobble, which is the difference between a customer acting on it and ignoring
 * it.
 *
 * Two of the things tested here are rules rather than preferences: a line
 * through one point is not a line, and a chart of one series needs no legend
 * and no colour identity.
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ScoreDelta } from "../ScoreDelta";
import { ScoreTrend } from "../ScoreTrend";
import type { PostureReading } from "@/lib/types";

function reading(score: number, day: number): PostureReading {
  return {
    observed_at: `2026-08-${String(day).padStart(2, "0")}T09:00:00Z`,
    security_score: score,
    open_finding_count: 5,
    findings_by_severity: {},
    risk_bands: {},
    attack_path_count: 1,
  };
}

describe("ScoreTrend", () => {
  it("says so plainly when there is nothing to compare yet", () => {
    // A line through one point is not a line, and an empty chart frame implies
    // data that is missing rather than data that does not exist yet.
    render(<ScoreTrend history={[reading(41, 1)]} />);

    expect(screen.getByText(/One scan so far/)).toBeInTheDocument();
    expect(screen.queryByText("Score over time")).not.toBeInTheDocument();
  });

  it("says so on a first-ever scan too", () => {
    render(<ScoreTrend history={[]} />);
    expect(screen.getByText(/One scan so far/)).toBeInTheDocument();
  });

  it("draws the line once two readings exist", () => {
    render(<ScoreTrend history={[reading(41, 1), reading(63, 2)]} />);

    // The heading is the signal that the component chose to chart. The marks
    // themselves are deliberately not asserted: jsdom gives every element a
    // zero-size box, so `ResponsiveContainer` measures 0x0 and correctly
    // renders nothing — an assertion on the SVG would be testing jsdom's
    // layout engine, and one on the absence of a legend would pass for the
    // same empty reason whether the rule held or not.
    expect(screen.getByText("Score over time")).toBeInTheDocument();
    expect(screen.queryByText(/One scan so far/)).not.toBeInTheDocument();
  });
});

describe("ScoreDelta", () => {
  it("shows an improvement as one", () => {
    const { container } = render(<ScoreDelta delta={12} />);
    expect(screen.getByText("↑")).toBeInTheDocument();
    // Asserted on the rendered text rather than as a standalone node: JSX
    // whitespace splits the number away from the words around it, and a
    // matcher that cared would be testing the spacing.
    expect(container.textContent).toContain("12");
  });

  it("does not dress a decline up as an improvement", () => {
    // The regression this exists for. The delta used to be an estimate that
    // could only ever be positive, so the arrow and the green were hard-coded;
    // measuring it makes a decline possible, and a green ↑ over a worsening
    // posture is a plain untruth.
    const { container } = render(<ScoreDelta delta={-9} />);

    expect(screen.getByText("↓")).toBeInTheDocument();
    expect(screen.queryByText("↑")).not.toBeInTheDocument();
    // The magnitude, not the minus sign: the arrow already carries direction.
    expect(container.textContent).toContain("9");
    expect(container.textContent).not.toContain("-9");
  });

  it("colours a decline as a problem rather than a success", () => {
    const { container } = render(<ScoreDelta delta={-9} />);
    expect(container.firstElementChild?.className).toContain("text-critical");
    expect(container.firstElementChild?.className).not.toContain("text-ok");
  });

  it("distinguishes no comparison from no change", () => {
    // A first scan has nothing to have moved from, and "No change" would claim
    // a comparison that was never made.
    render(<ScoreDelta delta={null} />);
    expect(screen.getByText("No previous scan to compare against")).toBeInTheDocument();
  });

  it("reports a genuine standstill as one", () => {
    render(<ScoreDelta delta={0} />);
    expect(screen.getByText("No change since last scan")).toBeInTheDocument();
  });
});
