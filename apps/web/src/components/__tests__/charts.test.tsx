/**
 * The rules the charts are not allowed to break.
 *
 * Every one of these is a way a security dashboard can lie quietly: a shape
 * that implies a measurement nobody took, a status carried by colour alone, or
 * motion that keeps moving for a reader who asked it not to.
 */
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { Sparkline } from "@/components/charts/Sparkline";
import { StackedBar } from "@/components/charts/StackedBar";
import { Bars } from "@/components/charts/Bars";

describe("Sparkline", () => {
  it("draws nothing from a single reading", () => {
    // A dot is not a trend. Drawing one invites the reader to see a direction
    // nobody has measured.
    const { container } = render(<Sparkline values={[4]} label="Critical" />);

    expect(container.querySelector("svg")).not.toBeInTheDocument();
  });

  it("describes the movement in words, not only in a line", () => {
    render(<Sparkline values={[1, 3, 6]} label="Critical findings" />);

    expect(
      screen.getByRole("img", { name: /Critical findings: risen from 1 to 6/ }),
    ).toBeInTheDocument();
  });

  it("survives a flat series without collapsing", () => {
    // A constant series has a zero range; dividing by it would put every point
    // at the same edge of the box, or produce NaN coordinates.
    const { container } = render(<Sparkline values={[2, 2, 2]} label="High" />);

    const path = container.querySelector("path")?.getAttribute("d") ?? "";
    expect(path).not.toContain("NaN");
    expect(screen.getByRole("img", { name: /held from 2 to 2/ })).toBeInTheDocument();
  });
});

describe("StackedBar", () => {
  it("labels every segment, never colour alone", () => {
    render(
      <StackedBar
        ariaLabel="Open findings by severity"
        segments={[
          { key: "CRITICAL", label: "Critical", value: 2, tone: "var(--sev-critical)" },
          { key: "LOW", label: "Low", value: 6, tone: "var(--sev-low)" },
        ]}
      />,
    );

    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText("Low")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Open findings by severity" })).toBeInTheDocument();
  });

  it("says there is nothing to break down rather than drawing an empty bar", () => {
    render(
      <StackedBar
        ariaLabel="Open findings by severity"
        segments={[
          { key: "CRITICAL", label: "Critical", value: 0, tone: "var(--sev-critical)" },
        ]}
      />,
    );

    expect(screen.getByText(/Nothing open to break down/)).toBeInTheDocument();
  });
});

describe("Bars", () => {
  it("measures every bar against the same scale", () => {
    const { container } = render(
      <MemoryRouter>
        <Bars
          ariaLabel="Risk bands"
          bars={[
            { key: "a", label: "Critical", value: 5, tone: "var(--sev-critical)" },
            { key: "b", label: "Low", value: 1, tone: "var(--sev-low)" },
          ]}
        />
      </MemoryRouter>,
    );

    const widths = [...container.querySelectorAll("span[style*='width']")].map(
      (node) => (node as HTMLElement).style.width,
    );
    // The largest fills the track and the rest are proportional to it, so two
    // bars can be compared by length rather than by reading their numbers.
    expect(widths).toEqual(["100%", "20%"]);
  });
});
