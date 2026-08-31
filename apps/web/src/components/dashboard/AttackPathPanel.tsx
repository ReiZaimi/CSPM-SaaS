import { Link } from "react-router-dom";
import { ArrowRightIcon, RouteIcon, ScissorsIcon } from "lucide-react";

import type { AttackPath } from "@/lib/types";
import { AttackPathRoute } from "@/components/graph/AttackPathRoute";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { buttonVariants } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/format";

/**
 * The shortest way in, drawn as the route it is.
 *
 * One path, not a graph. Every finding on this page is a fault seen alone; this
 * is the only panel that says three of them line up, and the thing a reader
 * does with it is cut one link — which a straight chain communicates and a
 * canvas of draggable nodes does not.
 *
 * The shortest route is shown because that ordering is itself the
 * recommendation: fewer hops is both likelier to be walked and cheaper to
 * sever.
 */
export function AttackPathPanel({
  paths,
  loading,
}: {
  paths: AttackPath[] | undefined;
  loading: boolean;
}) {
  const path = Array.isArray(paths) ? paths[0] : undefined;
  const cutIndex = path
    ? path.steps.findIndex(
        (step) =>
          path.cheapest_break?.source_id === step.source_id &&
          path.cheapest_break?.target_id === step.target_id,
      )
    : -1;

  return (
    <section
      aria-labelledby="critical-attack-path"
      className="flex flex-col overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <header className="flex items-start justify-between gap-4 px-5 py-4">
        <div>
          <h2 id="critical-attack-path" className="text-sm font-semibold">
            Shortest attack path
          </h2>
          <p className="mt-0.5 text-xs text-muted-foreground">
            What is wrong <em>together</em> — from something reachable to
            something worth taking
          </p>
        </div>
        <Link
          to="/attack-paths"
          className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "shrink-0")}
        >
          All paths
          <ArrowRightIcon data-icon="inline-end" />
        </Link>
      </header>

      <div className="flex flex-1 flex-col gap-4 border-t px-5 py-4">
        {loading && <Skeleton className="h-32 w-full" />}

        {!loading && !path && (
          // Never an all-clear. What counts as sensitive is declared per
          // subscription, so an estate that has classified nothing produces no
          // routes at all — which is a gap in what CloudGuard was told rather
          // than a clean environment.
          <p className="text-sm leading-relaxed text-muted-foreground">
            No route traced from an internet-facing asset to a sensitive one.
            What counts as sensitive is something you declare, so an estate with
            nothing classified shows none either —{" "}
            <Link to="/settings" className="underline underline-offset-2">
              declare what a subscription is worth
            </Link>{" "}
            to make this reading mean something.
          </p>
        )}

        {!loading && path && (
          <>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="flex min-w-0 items-center gap-2 text-sm font-medium">
                <RouteIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                <span className="truncate">
                  {path.entry.name}
                  <span className="mx-1.5 text-muted-foreground">→</span>
                  {path.target.name}
                </span>
              </p>
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  Exposure
                  <SeverityBadge level={path.entry.public_exposure} size="sm" />
                </span>
                <span className="flex items-center gap-1.5">
                  Sensitivity
                  <SeverityBadge level={path.target.data_sensitivity} size="sm" />
                </span>
              </div>
            </div>

            <AttackPathRoute steps={path.steps} cutIndex={cutIndex} />

            {path.cheapest_break && (
              <p className="flex items-start gap-2 rounded-lg border border-ok-border bg-ok-bg/60 px-3 py-2 text-xs leading-relaxed text-foreground">
                <ScissorsIcon className="mt-0.5 size-3.5 shrink-0 text-ok" aria-hidden />
                <span>
                  <span className="font-medium text-ok">Cut here: </span>
                  {path.cheapest_break.description}
                </span>
              </p>
            )}
          </>
        )}
      </div>
    </section>
  );
}
