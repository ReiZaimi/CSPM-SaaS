import { useMemo } from "react";

import { usePrefersReducedMotion } from "@/lib/motion";

/**
 * A line small enough to sit inside a number.
 *
 * Hand-written SVG rather than a charting library, for the reason the project
 * already applies to `ScoreRing`: this draws one polyline in a 24px band, and
 * pulling in a chart runtime per tile would cost more than the tiles do.
 *
 * **No axes, no grid, no tooltip, and that is a decision rather than an
 * omission.** A sparkline's job is shape — is this going up — and the exact
 * values are the large number printed beside it. It also lives inside a link on
 * the severity strip, and a hover layer inside a click target is a way of
 * making a row that cannot be clicked confidently. The series is instead
 * described to assistive technology in words, which is what a screen reader
 * needs from it anyway.
 */
export function Sparkline({
  values,
  label,
  tone = "currentColor",
  className,
}: {
  values: number[];
  /** What the line is of, for the reader who cannot see it. */
  label: string;
  tone?: string;
  className?: string;
}) {
  const reduced = usePrefersReducedMotion();

  const path = useMemo(() => {
    if (values.length < 2) return null;

    const width = 100;
    const height = 24;
    const max = Math.max(...values);
    const min = Math.min(...values);
    // A flat series is drawn flat, in the middle, rather than divided by zero
    // into a line that leaps between the top and bottom of the box.
    const span = max - min || 1;

    return values
      .map((value, index) => {
        const x = (index / (values.length - 1)) * width;
        const y = height - ((value - min) / span) * (height - 4) - 2;
        return `${index === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`;
      })
      .join(" ");
  }, [values]);

  // Two readings is the least that can show movement. Below it the honest
  // answer is nothing at all, not a dot implying a direction.
  if (!path) return null;

  const first = values[0];
  const last = values[values.length - 1];
  const direction = last > first ? "risen" : last < first ? "fallen" : "held";

  return (
    <svg
      viewBox="0 0 100 24"
      preserveAspectRatio="none"
      className={className}
      role="img"
      aria-label={`${label}: ${direction} from ${first} to ${last} across the last ${values.length} readings`}
    >
      <path
        d={path}
        fill="none"
        stroke={tone}
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
        // Drawn on, once, on mount. `pathLength` normalises the dash to 1 so
        // the animation does not depend on how long the real path happens to
        // be, and reduced motion gets the finished line rather than a slow one.
        pathLength={1}
        style={
          reduced
            ? undefined
            : {
                strokeDasharray: 1,
                strokeDashoffset: 1,
                animation: "cg-draw 700ms ease-out forwards",
              }
        }
      />
    </svg>
  );
}
