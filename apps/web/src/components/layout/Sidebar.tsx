import { NavLink } from "react-router-dom";
import {
  ActivityIcon,
  BoxesIcon,
  ClipboardCheckIcon,
  CloudIcon,
  GaugeIcon,
  ListChecksIcon,
  RadarIcon,
  RouteIcon,
  ShieldAlertIcon,
  WrenchIcon,
} from "lucide-react";

import { cn } from "@/lib/format";

/**
 * Navigation grouped by the question each screen answers.
 *
 * The old shell was ten flat tabs in a horizontal strip, in the order the pages
 * happened to be built. Nothing in it said that findings and attack paths are
 * two readings of the same problem, or that remediation comes after triage --
 * so a new user met the product as a list of nouns rather than as a workflow.
 *
 * The groups are the product loop: *what is my posture*, *what is wrong*, *what
 * am I doing about it*, *what is CloudGuard working from*. A reader who learns
 * those four questions can find any screen without reading the labels.
 */
export const NAV_GROUPS = [
  {
    label: "Posture",
    items: [{ to: "/", label: "Overview", icon: GaugeIcon, end: true }],
  },
  {
    label: "Exposure",
    items: [
      { to: "/findings", label: "Findings", icon: ShieldAlertIcon },
      { to: "/risks", label: "Risks", icon: RadarIcon },
      { to: "/attack-paths", label: "Attack paths", icon: RouteIcon },
      { to: "/assets", label: "Assets", icon: BoxesIcon },
    ],
  },
  {
    label: "Response",
    items: [
      { to: "/remediation", label: "Remediation", icon: WrenchIcon },
      { to: "/compliance", label: "Compliance", icon: ClipboardCheckIcon },
    ],
  },
  {
    label: "Evidence",
    items: [
      { to: "/scans", label: "Scans", icon: ActivityIcon },
      { to: "/rules", label: "Rules", icon: ListChecksIcon },
      { to: "/connections", label: "Cloud", icon: CloudIcon },
    ],
  },
] as const;

export function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav className="flex flex-col gap-5 px-3 py-4" aria-label="Main">
      {NAV_GROUPS.map((group) => (
        <div key={group.label} className="flex flex-col gap-1">
          <p className="px-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            {group.label}
          </p>
          {group.items.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={"end" in item ? item.end : undefined}
              onClick={onNavigate}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors",
                  "focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
                  isActive
                    ? "bg-sidebar-accent font-medium text-sidebar-accent-foreground"
                    : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
                )
              }
            >
              <item.icon className="size-4 shrink-0" aria-hidden />
              {item.label}
            </NavLink>
          ))}
        </div>
      ))}
    </nav>
  );
}
