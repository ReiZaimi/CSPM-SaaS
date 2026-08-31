import { useQuery } from "@tanstack/react-query";
import { RouteIcon, ScissorsIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { AttackPath, AttackPathMeta } from "@/lib/types";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { AttackPathRoute } from "@/components/graph/AttackPathRoute";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * Attack paths.
 *
 * Every other list in this product ranks by severity, which is the right order
 * for "what is wrong". This one ranks by hops, because it answers a different
 * question — what is wrong *together* — and there the shortest route is both
 * the most likely and the cheapest to break.
 *
 * The page deliberately leads with the route rather than the endpoints. "This
 * storage account is reachable" is an alarm; naming the three links between the
 * internet and it is a thing somebody can go and cut, and it shows them where.
 */
export function AttackPathsPage() {
  const t = useT();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["attack-paths"],
    queryFn: () =>
      api.get<AttackPath[]>("/api/v1/attack-paths").then((r) => ({
        paths: r.data,
        meta: r.meta as unknown as AttackPathMeta,
      })),
  });

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t.attackPaths.title}
        description={t.attackPaths.intro}
      />

      {isLoading && <CardsSkeleton />}

      {error && (
        <ErrorState
          title="Could not work out your attack paths"
          detail="CloudGuard could not reach its own API to rebuild the graph."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && data.paths.length === 0 && <NothingFound meta={data.meta} />}

      {data && data.paths.length > 0 && (
        <>
          <p className="text-xs text-muted-foreground">
            {data.meta.total} · {data.meta.entry_points}{" "}
            {t.attackPaths.entryPoints} · {data.meta.sensitive_targets}{" "}
            {t.attackPaths.sensitiveTargets}
          </p>
          <div className="flex flex-col gap-3">
            {data.paths.map((path) => (
              <PathCard
                key={`${path.entry.id}->${path.target.id}`}
                path={path}
              />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

/**
 * Three different nothings, and they call for three different actions.
 *
 * A single "no attack paths" would read as reassurance in all three cases, and
 * in two of them it is the opposite: nothing classified as sensitive means
 * CloudGuard does not know what would cost the customer anything, which is a
 * gap in what it was told rather than a clean environment.
 */
function NothingFound({ meta }: { meta: AttackPathMeta }) {
  const t = useT();

  if (meta.entry_points === 0 && meta.sensitive_targets === 0) {
    return (
      <EmptyState
        icon={RouteIcon}
        title={t.attackPaths.emptyNoScan}
        detail={t.attackPaths.emptyNoScanDetail}
      />
    );
  }
  if (meta.sensitive_targets === 0) {
    return (
      <EmptyState
        icon={RouteIcon}
        title={t.attackPaths.emptyNoTargets}
        detail={t.attackPaths.emptyNoTargetsDetail}
      />
    );
  }
  if (meta.entry_points === 0) {
    return (
      <EmptyState
        icon={RouteIcon}
        title={t.attackPaths.emptyNoEntry}
        detail={t.attackPaths.emptyNoEntryDetail}
      />
    );
  }
  return (
    <EmptyState
      icon={RouteIcon}
      title={t.attackPaths.emptyNoPaths}
      detail={t.attackPaths.emptyNoPathsDetail}
    />
  );
}

function PathCard({ path }: { path: AttackPath }) {
  const t = useT();

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <CardTitle className="text-sm">
              {path.entry.name} <span className="text-muted-foreground">→</span>{" "}
              {path.target.name}
            </CardTitle>
            <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <span className="flex items-center gap-1.5">
                {t.attackPaths.exposure}
                <SeverityBadge level={path.entry.public_exposure} size="sm" />
              </span>
              <span className="flex items-center gap-1.5">
                {t.attackPaths.sensitivity}
                <SeverityBadge level={path.target.data_sensitivity} size="sm" />
              </span>
            </div>
          </div>
          <div className="shrink-0 text-right">
            <p className="text-3xl font-semibold tabular-nums text-foreground">
              {path.hops}
            </p>
            <p className="text-xs text-muted-foreground">
              {path.hops === 1 ? t.attackPaths.oneHop : t.attackPaths.hops}
            </p>
          </div>
        </div>
      </CardHeader>

      <CardContent>
        <div className="border-t pt-3">
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            {t.attackPaths.route}
          </p>
          <AttackPathRoute
            className="mt-3"
            steps={path.steps}
            cutIndex={path.steps.findIndex(
              (step) =>
                path.cheapest_break?.source_id === step.source_id &&
                path.cheapest_break?.target_id === step.target_id,
            )}
          />
        </div>

        {/* The one hop worth cutting. Deliberately the product's "ok" colour
            rather than a warning: everything above it is the problem, and this
            is the part a person can act on. */}
        {path.cheapest_break && (
          <Alert className="mt-4 border-ok-border bg-ok-bg text-ok">
            <ScissorsIcon />
            <AlertTitle>{t.attackPaths.cutHere}</AlertTitle>
            <AlertDescription className="text-foreground">
              <p>{path.cheapest_break.description}</p>
              <p className="text-xs leading-relaxed text-muted-foreground">
                {t.attackPaths.cutHereDetail}
              </p>
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}
