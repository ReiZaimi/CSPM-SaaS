import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { useT } from "@/i18n";
import type { PostureReading } from "@/lib/types";
import { formatDateTime } from "@/lib/format";

/**
 * The security score, each time CloudGuard looked.
 *
 * A delta says something moved. This says whether that is a trend or a wobble,
 * which is the difference between a customer acting on it and ignoring it.
 *
 * Design notes, because two of them are rules rather than taste:
 *
 * **One series, one axis.** Open findings and attack-path counts are on a
 * completely different scale from a 0-100 score, so they are stat tiles beside
 * this rather than a second line against a second axis. Two y-scales in one
 * frame let any two shapes be made to look correlated.
 *
 * **The line is neutral ink, not a score colour.** Every palette token in this
 * product is a *status* colour with a fixed meaning, and colouring the line by
 * the value it is plotting would make the colour change as the data does — so a
 * customer would read the hue as a category rather than as the number already
 * on the axis. A single series needs no colour identity at all: nothing else is
 * in the frame to confuse it with, which is also why there is no legend.
 */
const INK = "var(--foreground)";
const GRID = "var(--border)";
const AXIS = "var(--muted-foreground)";
// Recharts paints the tooltip inline, so it does not inherit the surface the
// way a Tailwind-classed element does: unset, it stays white on a dark page.
const SURFACE = "var(--popover)";
const SURFACE_INK = "var(--popover-foreground)";

export function ScoreTrend({ history }: { history: PostureReading[] }) {
  const t = useT();

  // A line through one point is not a line. Two readings is the minimum that
  // can show movement, and below that the honest answer is a sentence rather
  // than a chart with nothing in it.
  if (history.length < 2) {
    return (
      <p className="text-xs leading-relaxed text-muted-foreground">{t.dashboard.trendTooShort}</p>
    );
  }

  const points = history.map((entry) => ({
    at: entry.observed_at,
    score: entry.security_score,
  }));

  return (
    <div>
      <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        {t.dashboard.trendTitle}
      </p>
      <div className="mt-2 h-28 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: -24 }}>
            {/* Recessive: the grid orients, it does not compete with the line. */}
            <CartesianGrid stroke={GRID} strokeDasharray="2 4" vertical={false} />
            <XAxis dataKey="at" hide />
            <YAxis
              domain={[0, 100]}
              ticks={[0, 50, 100]}
              tick={{ fontSize: 10, fill: AXIS }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              cursor={{ stroke: AXIS, strokeWidth: 1 }}
              labelFormatter={(value) => formatDateTime(String(value))}
              formatter={(value: number) => [value, t.dashboard.score]}
              contentStyle={{
                borderRadius: 8,
                border: `1px solid ${GRID}`,
                backgroundColor: SURFACE,
                color: SURFACE_INK,
                fontSize: 12,
              }}
              itemStyle={{ color: SURFACE_INK }}
              labelStyle={{ color: AXIS }}
            />
            <Line
              type="monotone"
              dataKey="score"
              stroke={INK}
              strokeWidth={2}
              // Points marked only where there are few enough to read. A dot on
              // every reading of a daily scan is a solid line of dots.
              dot={points.length <= 12 ? { r: 3, fill: INK } : false}
              activeDot={{ r: 4 }}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
