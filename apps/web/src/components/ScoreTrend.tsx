import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceArea,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { useT } from "@/i18n";
import type { PostureReading } from "@/lib/types";
import { usePrefersReducedMotion } from "@/lib/motion";
import { formatDateTime } from "@/lib/format";

/**
 * The security score, each time CloudGuard looked.
 *
 * A delta says something moved. This says whether that is a trend or a wobble,
 * which is the difference between a customer acting on it and ignoring it.
 *
 * Design notes, because three of them are rules rather than taste:
 *
 * **One series, one axis.** Open findings and attack-path counts are on a
 * completely different scale from a 0–100 score, so they are sparklines
 * elsewhere rather than a second line against a second axis. Two y-scales in
 * one frame let any two shapes be made to look correlated.
 *
 * **The line is neutral ink, not a score colour.** Every palette token in this
 * product is a *status* colour with a fixed meaning, and colouring the line by
 * the value it plots would make the hue change as the data does — so a reader
 * would take the colour for a category rather than the number already on the
 * axis. The meaning of the height instead lives in the bands behind it, which
 * are painted once and never move.
 *
 * **A fixed 0–100 axis.** Fitted to its own range, a wobble from 81 to 84
 * climbs as steeply as a recovery from 20 to 84.
 */
const INK = "var(--foreground)";
const GRID = "var(--border)";
const AXIS = "var(--muted-foreground)";
// Recharts paints the tooltip inline, so it does not inherit the surface the
// way a Tailwind-classed element does: unset, it stays white on a dark page.
const SURFACE = "var(--popover)";
const SURFACE_INK = "var(--popover-foreground)";

/**
 * The bands the score itself is read in.
 *
 * Painted at 5%, which is as loud as they may be: on a light surface an 8%
 * critical band reads as a pink wash across the whole plot, and a chart whose
 * background is the most saturated thing in it has stopped being a chart of the
 * line. They exist so a reader can see *where* 72 falls without the line
 * changing colour — nothing more.
 */
const BANDS = [
  { from: 0, to: 40, tone: "var(--sev-critical)" },
  { from: 40, to: 60, tone: "var(--sev-high)" },
  { from: 60, to: 85, tone: "var(--sev-medium)" },
  { from: 85, to: 100, tone: "var(--sev-ok)" },
];

export function ScoreTrend({ history }: { history: PostureReading[] }) {
  const t = useT();
  const reduced = usePrefersReducedMotion();

  // A line through one point is not a line. Two readings is the minimum that
  // can show movement, and below that the honest answer is a sentence rather
  // than a chart with nothing in it.
  if (history.length < 2) {
    return (
      <p className="text-xs leading-relaxed text-muted-foreground">
        {t.dashboard.trendTooShort}
      </p>
    );
  }

  const points = history.map((entry) => ({
    at: entry.observed_at,
    score: entry.security_score,
    open: entry.open_finding_count,
  }));

  const first = points[0];
  const last = points[points.length - 1];

  return (
    <div className="h-40 w-full">
      {/* The chart in words. A canvas of marks is nothing to a screen reader,
          and the shape is the only thing this panel is for — so the series is
          summarised in text that is always present, not in a title attribute
          that only a mouse can reach. */}
      <p className="sr-only">
        Score over time: {points.length} readings, from {first.score} on{" "}
        {formatDateTime(first.at)} to {last.score} on {formatDateTime(last.at)}.
      </p>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={points} margin={{ top: 4, right: 12, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id="cg-score-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={INK} stopOpacity={0.1} />
              <stop offset="100%" stopColor={INK} stopOpacity={0} />
            </linearGradient>
          </defs>

          {/* What the height means, painted once. Faint enough to stay behind
              the data and fixed enough that the reader can learn it. */}
          {BANDS.map((band) => (
            <ReferenceArea
              key={band.from}
              y1={band.from}
              y2={band.to}
              fill={band.tone}
              fillOpacity={0.05}
              stroke="none"
              ifOverflow="extendDomain"
            />
          ))}

          <CartesianGrid stroke={GRID} strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey="at"
            tickFormatter={(value: string) =>
              new Date(value).toLocaleDateString(undefined, {
                day: "numeric",
                month: "short",
              })
            }
            tick={{ fill: AXIS, fontSize: 11 }}
            tickLine={false}
            axisLine={{ stroke: GRID }}
            minTickGap={40}
          />
          <YAxis
            domain={[0, 100]}
            ticks={[0, 50, 100]}
            tick={{ fill: AXIS, fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            // Wide enough for three digits: at 44 with a negative left margin
            // the "100" lost its first character, which is the one that says
            // what scale this is.
            width={32}
          />
          <Tooltip
            cursor={{ stroke: GRID, strokeWidth: 1 }}
            contentStyle={{
              background: SURFACE,
              color: SURFACE_INK,
              border: "1px solid var(--border)",
              borderRadius: "var(--radius)",
              fontSize: "0.75rem",
            }}
            labelFormatter={(value: string) => formatDateTime(value)}
            formatter={(value: number, name: string) => [
              value,
              name === "score" ? "Security score" : "Open findings",
            ]}
          />
          <Area
            type="monotone"
            dataKey="score"
            stroke={INK}
            strokeWidth={2}
            fill="url(#cg-score-fill)"
            // Every reading is marked: these are the moments CloudGuard
            // actually looked, and a smooth line with no points invites the
            // reader to believe in measurements between them that do not exist.
            dot={{ r: 2.5, fill: SURFACE, stroke: INK, strokeWidth: 1.5 }}
            activeDot={{ r: 4.5, fill: INK, stroke: SURFACE, strokeWidth: 2 }}
            isAnimationActive={!reduced}
            animationDuration={700}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
