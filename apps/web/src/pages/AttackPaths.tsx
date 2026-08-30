import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { AttackPath, AttackPathMeta, AttackPathStep } from "@/lib/types";
import { useT } from "@/i18n";
import { Badge, Card, EmptyState, ErrorNote, Spinner } from "@/components/ui";

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
        <p className="mt-1 max-w-3xl text-sm text-stone-500">{t.attackPaths.intro}</p>
      </div>

      {isLoading && <Spinner text={t.common.loading} />}
      {error && <ErrorNote message={t.common.error} onRetry={() => refetch()} />}

      {data && data.paths.length === 0 && <NothingFound meta={data.meta} />}

      {data && data.paths.length > 0 && (
        <>
          <p className="text-xs text-stone-500">
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
          <p className="text-sm font-medium text-stone-900">
            {path.entry.name} <span className="text-stone-400">→</span> {path.target.name}
          </p>
          <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-stone-500">
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
          <p className="text-3xl font-semibold tabular-nums text-stone-900">{path.hops}</p>
          <p className="text-xs text-stone-400">
            {path.hops === 1 ? t.attackPaths.oneHop : t.attackPaths.hops}
          </p>
        </div>
      </div>

      <div className="mt-4 border-t border-stone-100 pt-3">
        <p className="text-[11px] font-medium uppercase tracking-wide text-stone-400">
          {t.attackPaths.route}
        </p>
        <ol className="mt-2 space-y-1.5">
          {path.steps.map((step, index) => (
            <Step
              key={`${step.source_id}-${step.relationship}-${step.target_id}`}
              step={step}
              index={index}
              isCut={
                path.cheapest_break?.source_id === step.source_id &&
                path.cheapest_break?.target_id === step.target_id
              }
            />
          ))}
        </ol>
      </div>

      {path.cheapest_break && (
        <div className="mt-4 rounded-lg border border-ok-border bg-ok-bg px-4 py-3">
          <p className="text-sm font-medium text-ok">{t.attackPaths.cutHere}</p>
          <p className="mt-1 text-sm text-stone-800">{path.cheapest_break.description}</p>
          <p className="mt-1.5 text-xs leading-relaxed text-stone-600">
            {t.attackPaths.cutHereDetail}
          </p>
        </div>
      )}
    </Card>
  );
}

function Step({
  step,
  index,
  isCut,
}: {
  step: AttackPathStep;
  index: number;
  isCut: boolean;
}) {
  return (
    <li className="flex items-start gap-2.5 text-sm">
      <span
        className={
          // The severable link is marked in the route itself as well as called
          // out below it. Reading the route and then reading the fix separately
          // makes the customer hold both in their head to see which hop the fix
          // refers to.
          isCut
            ? "mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-ok-border bg-ok-bg text-[10px] font-medium text-ok"
            : "mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-stone-200 bg-white text-[10px] font-medium text-stone-500"
        }
      >
        {index + 1}
      </span>
      <span className={isCut ? "text-stone-900" : "text-stone-600"}>{step.description}</span>
    </li>
  );
}
