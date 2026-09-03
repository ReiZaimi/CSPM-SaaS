import { useEffect, useState } from "react";
import { Link, Outlet, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { MenuIcon, PanelLeftCloseIcon, PanelLeftOpenIcon } from "lucide-react";

import { api, auth } from "@/lib/api";
import type { CloudAccount, Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { ShieldMark } from "@/components/Brand";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { AccountMenu } from "@/components/AccountMenu";
import { SidebarNav } from "@/components/layout/Sidebar";
import { CommandPalette } from "@/components/layout/CommandPalette";
import { NotificationBell } from "@/components/layout/NotificationBell";
import { ScanIndicator } from "@/components/layout/ScanIndicator";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Toaster } from "@/components/ui/sonner";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/format";

/** Where the rail preference lives. Per browser, like the theme. */
const COLLAPSE_KEY = "cloudguard.sidebar.collapsed";

/**
 * The application shell.
 *
 * A sidebar rather than the horizontal strip this replaced, for a reason that
 * is about the product rather than about fashion: ten peer tabs cannot express
 * that findings, risks and attack paths are three readings of one problem while
 * scans and connections are the machinery underneath. A column has room to
 * group them, and the groups are the security workflow (`layout/Sidebar.tsx`).
 *
 * The header keeps only what is true across every page: who you are, which
 * organization you are looking at, and whether CloudGuard is currently reading
 * your cloud. The last of those is new and is the one people ask for -- a scan
 * takes minutes, and previously nothing outside the scans page said one was
 * running.
 */
export function Shell() {
  const t = useT();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);

  // A choice about the shape of the workspace, so it is remembered: somebody
  // working on a small laptop should not re-collapse the sidebar every morning.
  // Read lazily and defensively -- a browser with storage disabled must still
  // render an application.
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return window.localStorage.getItem(COLLAPSE_KEY) === "1";
    } catch {
      return false;
    }
  });

  useEffect(() => {
    try {
      window.localStorage.setItem(COLLAPSE_KEY, collapsed ? "1" : "0");
    } catch {
      // Nothing to do: the preference simply does not survive the session.
    }
  }, [collapsed]);

  const { data: orgs, isLoading } = useQuery({
    queryKey: ["organizations"],
    queryFn: () =>
      api.get<Organization[]>("/api/v1/organizations").then((r) => r.data),
  });

  // Both of these used to run during render, which meant navigating and writing
  // to a store that notifies subscribers while React was still rendering.
  useEffect(() => {
    if (isLoading || !orgs) return;

    // A signed-in user with no organization has not finished signing up.
    if (orgs.length === 0) {
      navigate("/onboarding", { replace: true });
      return;
    }

    // Only default when the stored choice names nothing real — otherwise this
    // would immediately undo whatever the user just picked.
    const selected = orgs.find((o) => o.id === auth.organizationId);
    if (!selected) auth.organizationId = orgs[0].id;
  }, [isLoading, orgs, navigate]);

  const current = orgs?.find((o) => o.id === auth.organizationId) ?? orgs?.[0];

  return (
    // One provider for the whole application: without it every tooltip runs its
    // own delay, so crossing a row of them makes each one wait again.
    <TooltipProvider delay={200}>
      <div className="min-h-screen bg-background">
        {/* Fixed rather than scrolling with the page: navigation that scrolls
          away makes a long findings table a one-way trip. */}
        <aside
          className={cn(
            "fixed inset-y-0 left-0 z-30 hidden border-r bg-sidebar transition-[width] duration-200 lg:flex lg:flex-col",
            collapsed ? "w-14" : "w-60",
          )}
        >
          <div
            className={cn(
              "flex h-14 shrink-0 items-center border-b",
              collapsed ? "justify-center px-2" : "gap-2.5 px-4",
            )}
          >
            <ShieldMark className="size-5" />
            {!collapsed && (
              <span className="text-sm font-semibold tracking-tight">
                {t.app.name}
              </span>
            )}
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">
            <SidebarNav collapsed={collapsed} />
          </div>
          <div
            className={cn(
              "flex shrink-0 items-center gap-1 border-t",
              collapsed ? "flex-col p-2" : "p-3",
            )}
          >
            <ConnectionBadge collapsed={collapsed} />
            <Button
              variant="ghost"
              size="icon-sm"
              className={collapsed ? "" : "ml-auto"}
              onClick={() => setCollapsed((v) => !v)}
              aria-label={
                collapsed ? "Expand navigation" : "Collapse navigation"
              }
              aria-expanded={!collapsed}
            >
              {collapsed ? <PanelLeftOpenIcon /> : <PanelLeftCloseIcon />}
            </Button>
          </div>
        </aside>

        <div
          className={cn(
            "transition-[padding] duration-200",
            collapsed ? "lg:pl-14" : "lg:pl-60",
          )}
        >
          <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b bg-background/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/80 sm:px-6">
            <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
              <SheetTrigger
                render={
                  <Button
                    variant="ghost"
                    size="icon"
                    className="lg:hidden"
                    aria-label="Open navigation"
                  />
                }
              >
                <MenuIcon />
              </SheetTrigger>
              <SheetContent side="left" className="w-64 p-0">
                <SheetTitle className="flex h-14 items-center gap-2.5 border-b px-4 text-sm font-semibold">
                  <ShieldMark className="size-5" />
                  {t.app.name}
                </SheetTitle>
                <SidebarNav onNavigate={() => setMobileOpen(false)} />
              </SheetContent>
            </Sheet>

            <div className="flex items-center gap-2 lg:hidden">
              <span className="text-sm font-semibold tracking-tight">
                {t.app.name}
              </span>
            </div>

            <div className="ml-auto flex items-center gap-3">
              <CommandPalette />
              <ScanIndicator />
              {/* After the scan indicator and before the settings: what is
                  happening now, then what happened, then how the app looks. */}
              <NotificationBell />
              <ThemeToggle />
              <AccountMenu organizations={orgs ?? []} current={current} />
            </div>
          </header>

          <main className="mx-auto max-w-[1400px] px-4 py-6 sm:px-6 lg:py-8">
            {/* Per-page, inside the chrome. A page that throws is one broken
                screen the reader can navigate away from, rather than a product
                that vanished -- and the root boundary is still behind this for
                anything the shell itself does. */}
            <ErrorBoundary variant="page">
              <Outlet />
            </ErrorBoundary>
          </main>
        </div>

        {/* Mounted once, here, because an action's outcome outlives the panel it
          was taken in: marking a task done navigates nowhere, and the answer --
          that CloudGuard will look again rather than that the finding is now
          closed -- has to arrive somewhere that is always on screen. */}
        <Toaster position="bottom-right" />
      </div>
    </TooltipProvider>
  );
}

/**
 * Whether CloudGuard can see anything at all.
 *
 * Sits at the foot of the sidebar because it is the precondition for every
 * number on every other screen: a product showing a security score of 100 over
 * an environment it has never connected to is not reassuring, it is wrong.
 */
function ConnectionBadge({ collapsed = false }: { collapsed?: boolean }) {
  const { data } = useQuery({
    queryKey: ["cloud-accounts"],
    queryFn: () =>
      api.get<CloudAccount[]>("/api/v1/cloud-accounts").then((r) => r.data),
    retry: false,
  });

  const count = data?.length ?? 0;
  const scannable = data?.filter((a) => a.is_scannable).length ?? 0;

  const summary =
    count === 0
      ? "No cloud connected"
      : scannable > 0
        ? `${scannable} subscription${scannable === 1 ? "" : "s"} monitored`
        : "Connected, not ready to scan";

  // On the rail there is room for the state and not for the sentence. The dot
  // keeps its meaning and the sentence moves to a tooltip, rather than the
  // precondition for every number in the product disappearing with the labels.
  if (collapsed) {
    return (
      <Tooltip>
        <TooltipTrigger
          render={
            <Link
              to="/connections"
              aria-label={summary}
              className="flex size-7 items-center justify-center rounded-md hover:bg-sidebar-accent/60"
            />
          }
        >
          <span
            className={cn(
              "size-2 rounded-full",
              count === 0
                ? "bg-muted-foreground"
                : scannable > 0
                  ? "bg-ok"
                  : "bg-medium",
            )}
          />
        </TooltipTrigger>
        <TooltipContent side="right">{summary}</TooltipContent>
      </Tooltip>
    );
  }

  if (count === 0) {
    return (
      <a
        href="/connections"
        className="flex items-center gap-2 rounded-md border border-dashed px-2.5 py-2 text-xs text-muted-foreground transition-colors hover:border-solid hover:text-foreground"
      >
        <span className="size-1.5 shrink-0 rounded-full bg-muted-foreground" />
        No cloud connected
      </a>
    );
  }

  return (
    <div className="flex items-center gap-2 px-2.5 py-2 text-xs text-muted-foreground">
      <span
        className={
          scannable > 0
            ? "size-1.5 shrink-0 rounded-full bg-ok"
            : "size-1.5 shrink-0 rounded-full bg-medium"
        }
      />
      {scannable > 0
        ? `${scannable} subscription${scannable === 1 ? "" : "s"} monitored`
        : "Connected, not ready to scan"}
    </div>
  );
}
