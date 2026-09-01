import { NavLink } from "react-router-dom";

import { NAV_GROUPS } from "@/components/layout/nav";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/format";

/**
 * The navigation, in two widths.
 *
 * Collapsed it keeps the icons and drops the words, which is the trade a
 * fourteen-inch screen actually wants: the four groups are the product's
 * workflow and their order is what a returning reader navigates by, so the rail
 * keeps both the order and the grouping and gives up only the labels — and each
 * icon still says its own name on hover and to a screen reader.
 */
export function SidebarNav({
  onNavigate,
  collapsed = false,
}: {
  onNavigate?: () => void;
  collapsed?: boolean;
}) {
  return (
    <nav
      className={cn("flex flex-col gap-5 py-4", collapsed ? "px-2" : "px-3")}
      aria-label="Main"
    >
      {NAV_GROUPS.map((group) => (
        <div key={group.label} className="flex flex-col gap-1">
          {collapsed ? (
            // A rule rather than a heading: the grouping is still information
            // even when there is no room to name it.
            <span className="mx-2 mb-1 border-t" aria-hidden />
          ) : (
            <p className="px-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              {group.label}
            </p>
          )}
          {group.items.map((item) => {
            const link = (
              <NavLink
                key={item.to}
                to={item.to}
                end={"end" in item ? item.end : undefined}
                onClick={onNavigate}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-2.5 rounded-md py-1.5 text-sm transition-colors",
                    collapsed ? "justify-center px-2" : "px-2",
                    "focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
                    isActive
                      ? "bg-sidebar-accent font-medium text-sidebar-accent-foreground"
                      : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
                  )
                }
              >
                <item.icon className="size-4 shrink-0" aria-hidden />
                {collapsed ? (
                  <span className="sr-only">{item.label}</span>
                ) : (
                  item.label
                )}
              </NavLink>
            );

            if (!collapsed) return link;

            return (
              <Tooltip key={item.to}>
                <TooltipTrigger render={link} />
                <TooltipContent side="right">{item.label}</TooltipContent>
              </Tooltip>
            );
          })}
        </div>
      ))}
    </nav>
  );
}
