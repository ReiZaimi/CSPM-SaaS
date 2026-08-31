import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { AttackPath, AttackPathMeta } from "@/lib/types";
import { useT } from "@/i18n";
import { Badge, Card, EmptyState, ErrorNote, Spinner } from "@/components/ui";
import { AttackPathRoute } from "@/components/graph/AttackPathRoute";

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
      api
        .get<AttackPath[]>("/api/v1/attack-paths")
        .then((r) => ({ paths: r.data, meta: r.meta as unknown as AttackPathMeta })),
  });

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{t.attackPaths.title}</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t.attackPaths.intro}</p>
      </div>

      {isLoading && <Spinner text={t.common.loading} />}
      {error && <ErrorNote message={t.common.error} onRetry={() => refetch()} />}

      {data && data.paths.length === 0 && <NothingFound meta={data.meta} />}

      {data && data.paths.length > 0 && (
        <>
          <p className="text-xs text-muted-foreground">
            {data.meta.total} · {data.meta.entry_points} {t.attackPaths.entryPoints} ·{" "}
            {data.meta.sensitive_targets} {t.attackPaths.sensitiveTargets}
          </p>
          <div className="space-y-3">
            {data.paths.map((path) => (
              <PathCard key={`${path.entry.id}->${path.target.id}`} path={path} />
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
      <EmptyState title={t.attackPaths.emptyNoScan} detail={t.attackPaths.emptyNoScanDetail} />
    );
  }
  if (meta.sensitive_targets === 0) {
    return (
      <EmptyState
        title={t.attackPaths.emptyNoTargets}
        detail={t.attackPaths.emptyNoTargetsDetail}
      />
    );
  }
  if (meta.entry_points === 0) {
    return (
      <EmptyState title={t.attackPaths.emptyNoEntry} detail={t.attackPaths.emptyNoEntryDetail} />
    );
  }
  return (
    <EmptyState title={t.attackPaths.emptyNoPaths} detail={t.attackPaths.emptyNoPathsDetail} />
  );
}

function PathCard({ path }: { path: AttackPath }) {
  const t = useT();

  return (
    <Card>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-foreground">
            {path.entry.name} <span className="text-muted-foreground">→</span> {path.target.name}
          </p>
          <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
            <span className="flex items-center gap-1.5">
              {t.attackPaths.exposure}
              <Badge level={path.entry.public_exposure} className="text-[10px]" />
            </span>
            <span className="flex items-center gap-1.5">
              {t.attackPaths.sensitivity}
              <Badge level={path.target.data_sensitivity} className="text-[10px]" />
            </span>
          </div>
        </div>
        <div className="text-right">
          <p className="text-3xl font-semibold tabular-nums text-foreground">{path.hops}</p>
          <p className="text-xs text-muted-foreground">
            {path.hops === 1 ? t.attackPaths.oneHop : t.attackPaths.hops}
          </p>
        </div>
      </div>

      <div className="mt-4 border-t pt-3">
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

      {path.cheapest_break && (
        <div className="mt-4 rounded-lg border border-ok-border bg-ok-bg px-4 py-3">
          <p className="text-sm font-medium text-ok">{t.attackPaths.cutHere}</p>
          <p className="mt-1 text-sm text-foreground">{path.cheapest_break.description}</p>
          <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">
            {t.attackPaths.cutHereDetail}
          </p>
        </div>
      )}
    </Card>
  );
}
