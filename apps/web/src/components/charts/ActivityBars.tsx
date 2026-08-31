import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { usePrefersReducedMotion } from "@/lib/motion";

export type ActivityWeek = {
  week: string;
  detected: number;
  resolved: number;
  reopened: number;
};

const GRID = "var(--border)";
const AXIS = "var(--muted-foreground)";
const SURFACE = "var(--popover)";
const SURFACE_INK = "var(--popover-foreground)";

/**
 * What happened, week by week: raised, fixed, and come back.
 *
 * Three series, and they are statuses rather than arbitrary categories, so they
 * wear the status scale — raised is the problem colour, fixed is the good one,
 * and a fix that did not hold is critical, because that is what it is.
 *
 * **Reopenings are never subtracted from fixes.** A fix that regressed
 * happened; netting the two would hide exactly the pattern a security team
 * needs to see, and would let a bad week average into an unremarkable one.
 *
 * Grouped rather than stacked. Stacking would make the height of a week mean
 * "amount of activity", which is not a quantity anybody acts on; side by side,
 * the comparison the reader wants — did we fix more than came back — is a
 * comparison of two adjacent lengths.
 */
export function ActivityBars({ weeks }: { weeks: ActivityWeek[] }) {
  const reduced = usePrefersReducedMotion();

  const data = weeks.map((week) => ({
    ...week,
    label: new Date(week.week).toLocaleDateString(undefined, {
      day: "numeric",
      month: "short",
    }),
  }));

  return (
    <div className="h-40 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -24 }} barGap={2}>
          <CartesianGrid stroke={GRID} strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ fill: AXIS, fontSize: 11 }}
            tickLine={false}
            axisLine={{ stroke: GRID }}
            minTickGap={16}
          />
          <YAxis
            allowDecimals={false}
            tick={{ fill: AXIS, fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            width={40}
          />
          <Tooltip
            cursor={{ fill: "var(--muted)", opacity: 0.4 }}
            contentStyle={{
              background: SURFACE,
              color: SURFACE_INK,
              border: "1px solid var(--border)",
              borderRadius: "var(--radius)",
              fontSize: "0.75rem",
            }}
            labelFormatter={(value: string) => `Week of ${value}`}
          />
          {/* Three series, so a legend is not optional: identity must never be
              carried by colour alone. */}
          <Legend
            iconType="square"
            iconSize={8}
            wrapperStyle={{ fontSize: "0.7rem", color: AXIS, paddingTop: 4 }}
          />
          <Bar
            dataKey="detected"
            name="Raised"
            fill="var(--sev-medium)"
            radius={[3, 3, 0, 0]}
            isAnimationActive={!reduced}
            animationDuration={600}
          />
          <Bar
            dataKey="resolved"
            name="Verified fixed"
            fill="var(--sev-ok)"
            radius={[3, 3, 0, 0]}
            isAnimationActive={!reduced}
            animationDuration={600}
          />
          <Bar
            dataKey="reopened"
            name="Came back"
            fill="var(--sev-critical)"
            radius={[3, 3, 0, 0]}
            isAnimationActive={!reduced}
            animationDuration={600}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
