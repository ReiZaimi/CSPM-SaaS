import {
  ActivityIcon,
  BoxesIcon,
  ClipboardCheckIcon,
  CloudIcon,
  GaugeIcon,
  FileTextIcon,
  GitCompareArrowsIcon,
  ListChecksIcon,
  RadarIcon,
  RouteIcon,
  ShieldAlertIcon,
  WrenchIcon,
} from "lucide-react";

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
    items: [
      { to: "/", label: "Overview", icon: GaugeIcon, end: true },
      // Beside the overview rather than under Evidence: both answer "where do
      // I stand", one as a state and one as the movement that produced it.
      { to: "/changes", label: "Changes", icon: GitCompareArrowsIcon },
      // The same posture, fixed to a moment and made portable. Beside the two
      // live readings rather than under Evidence: a report is what this group
      // produces, not something CloudGuard reads from.
      { to: "/reports", label: "Reports", icon: FileTextIcon },
    ],
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
