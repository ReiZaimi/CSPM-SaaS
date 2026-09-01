/**
 * The dashboard's anchor.
 *
 * "82" alone invites exactly two questions — out of what, and is that good —
 * and a panel that answers neither makes the reader hunt for both.
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ScorePanel } from "@/components/dashboard/ScorePanel";

describe("ScorePanel", () => {
  it("gives the number a scale and a meaning", () => {
    render(<ScorePanel score={82} delta={null} history={[]} scannedAt={null} />);

    expect(screen.getByText("82")).toBeInTheDocument();
    expect(screen.getByText("/ 100")).toBeInTheDocument();
    expect(screen.getByText("Needs attention")).toBeInTheDocument();
  });

  it("does not claim a trend it cannot measure", () => {
    // No earlier reading is not "no change": the two mean opposite things to
    // somebody deciding whether remediation is working.
    render(<ScorePanel score={70} delta={null} history={[]} scannedAt={null} />);

    expect(screen.getByText(/no previous scan/i)).toBeInTheDocument();
  });

  it("exposes the proportion to assistive technology", () => {
    render(<ScorePanel score={41} delta={-3} history={[]} scannedAt={null} />);

    expect(screen.getByRole("meter", { name: /security score/i })).toHaveAttribute(
      "aria-valuenow",
      "41",
    );
  });
});
