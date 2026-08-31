import { Link } from "react-router-dom";

import { cn } from "@/lib/format";

export type Bar = {
  key: string;
  label: string;
  value: number;
  /**
   * What the bar is measured against, when that is something other than the
   * largest bar in the set — a share of a total, or a percentage of 100.
   * Shown as a denominator rather than drawn as a second bar.
   */
  of?: number;
  /** Suppress the denominator where it would repeat on every row. */
  hideDenominator?: boolean;
  tone: string;
  to?: string;
};

/**
 * A ranked comparison, drawn as lengths from a common baseline.
 *
 * The form ranking asks for, and the one a ring cannot do: lengths on a shared
 * left edge are compared exactly, angles around a circle are compared badly.
 * Every bar is measured against the largest value in the set, so the longest
 * fills the track and the rest are honestly proportional to it.
 *
 * Plain elements again. This is a list of widths; a chart runtime would add a
 * canvas and a resize observer to draw what a div already draws.
 */
export function Bars({
  bars,
  ariaLabel,
  className,
}: {
  bars: Bar[];
  ariaLabel: string;
  className?: string;
}) {
  const max = Math.max(...bars.map((bar) => bar.of ?? bar.value), 1);

  return (
    <ul className={cn("flex flex-col gap-2.5", className)} aria-label={ariaLabel}>
      {bars.map((bar) => {
        const width = ((bar.of ?? bar.value) === 0 ? 0 : bar.value / max) * 100;

        const row = (
          <>
            <span className="w-24 shrink-0 truncate text-xs text-muted-foreground">
              {bar.label}
            </span>
            <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
              <span
                className="block h-full rounded-full transition-[width] duration-700 ease-out"
                style={{ width: `${width}%`, background: bar.tone }}
              />
            </span>
            <span
              className={cn(
                "w-10 shrink-0 text-right text-xs tabular-nums",
                bar.value === 0 ? "text-muted-foreground" : "font-medium",
              )}
            >
              {bar.value}
              {bar.of !== undefined && !bar.hideDenominator && (
                <span className="text-muted-foreground">/{bar.of}</span>
              )}
            </span>
          </>
        );

        return (
          <li key={bar.key}>
            {bar.to ? (
              <Link
                to={bar.to}
                className="flex items-center gap-3 rounded-md py-0.5 transition-colors hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
              >
                {row}
              </Link>
            ) : (
              <div className="flex items-center gap-3 py-0.5">{row}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
