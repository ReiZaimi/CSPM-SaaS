import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Risk } from "@/lib/types";
import { useT } from "@/i18n";
import { Badge, Card, EmptyState, ErrorNote, Spinner, StatusPill } from "@/components/ui";

export function RisksPage() {
  const t = useT();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["risks"],
    queryFn: () => api.get<Risk[]>("/api/v1/risks").then((r) => r.data),
  });

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{t.risks.title}</h1>
        <p className="mt-1 text-sm text-stone-500">
          A finding is what we observed. A risk is what it means for this asset, with this data,
          at this level of exposure.
        </p>
      </div>

      {isLoading && <Spinner text={t.common.loading} />}
      {error && <ErrorNote message={t.common.error} onRetry={() => refetch()} />}
      {data && data.length === 0 && <EmptyState title={t.risks.empty} />}

      <div className="space-y-3">
        {/* Both kinds in one list, deliberately. A route outranking the
            findings inside it is only visible where they are ranked together —
            on a page of its own it would be a second opinion nobody compares. */}
        {data?.map((risk) =>
          risk.kind === "FINDING" ? (
            <FindingRiskCard key={risk.id} risk={risk} />
          ) : (
            <ScenarioCard key={risk.id} risk={risk} />
          ),
        )}
      </div>
    </div>
  );
}

/**
 * A route, scored as one thing.
 *
 * Rendered differently from a finding risk rather than as one with extra
 * fields, because the six weighted components do not apply: a scenario is
 * floored at its worst member and amplified for being short, and showing it
 * under "asset criticality / data sensitivity / exploitability" would invite
 * the reader to check numbers that were never used.
 *
 * Both scenario kinds render here, and the default is deliberately this way
 * round: anything that is not a finding risk was scored by the scenario
 * formula, so a new template added later shows honest arithmetic rather than
 * falling through to a card that would display components nobody computed.
 */
function ScenarioCard({ risk }: { risk: Risk }) {
  const t = useT();
  const breakdown = risk.score_breakdown;
  const capped = (breakdown.uncapped ?? 0) > 100;
  const escalation = risk.kind === "ESCALATION";

  return (
    <Card>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Badge level={risk.risk_level} />
            <StatusPill status={risk.status} />
            <span className="inline-flex items-center rounded-full border border-stone-300 bg-white px-2 py-0.5 text-xs font-medium text-stone-600">
              {escalation ? t.risks.escalationBadge : t.risks.scenarioBadge}
            </span>
          </div>
          <p className="mt-2 text-sm font-medium text-stone-900">{risk.title}</p>
          <p className="mt-1 text-xs text-stone-500">
            {escalation ? t.risks.escalationIntro : t.risks.scenarioIntro}
          </p>
        </div>
        <div className="text-right">
          <p className="text-3xl font-semibold tabular-nums text-stone-900">
            {Number(risk.risk_score).toFixed(0)}
          </p>
          <p className="text-xs text-stone-400">risk score</p>
        </div>
      </div>

      {risk.path.length > 0 && (
        <div className="mt-4 border-t border-stone-100 pt-3">
          <p className="text-[11px] font-medium uppercase tracking-wide text-stone-400">
            {t.risks.routeLabel}
          </p>
          <ol className="mt-2 space-y-1.5">
            {risk.path.map((step, index) => (
              <li
                key={`${step.source_id}-${step.relationship}-${step.target_id}`}
                className="flex items-start gap-2.5 text-sm text-stone-600"
              >
                <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-stone-200 bg-white text-[10px] font-medium text-stone-500">
                  {index + 1}
                </span>
                {step.description}
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* The arithmetic, in the terms the score was actually built from. A
          customer asking why this outranks the finding inside it gets the
          answer rather than a number. */}
      <div className="mt-4 flex flex-wrap gap-x-6 gap-y-2 border-t border-stone-100 pt-3 text-xs">
        <span className="text-stone-500">
          {t.risks.worstMember}{" "}
          <strong className="text-stone-800">{breakdown.worst_member ?? "—"}</strong>
        </span>
        <span className="text-stone-500">
          {t.risks.amplifier}{" "}
          <strong className="text-stone-800">+{breakdown.amplifier ?? 0}</strong>
        </span>
        <span className="text-stone-500">
          Hops <strong className="text-stone-800">{breakdown.hops ?? risk.path.length}</strong>
        </span>
        {capped && <span className="text-stone-400">{t.risks.cappedNote}</span>}
      </div>
    </Card>
  );
}

function FindingRiskCard({ risk }: { risk: Risk }) {
  return (
    <Card>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <Badge level={risk.risk_level} />
            <StatusPill status={risk.status} />
          </div>
          <p className="mt-2 text-sm font-medium text-stone-900">{risk.title}</p>
          <p className="mt-1 max-w-3xl text-sm text-stone-600">{risk.description}</p>
        </div>
        <div className="text-right">
          <p className="text-3xl font-semibold tabular-nums text-stone-900">
            {Number(risk.risk_score).toFixed(0)}
          </p>
          <p className="text-xs text-stone-400">risk score</p>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap gap-x-6 gap-y-2 border-t border-stone-100 pt-3 text-xs">
        <Factor label="Asset criticality" level={risk.asset_criticality} />
        <Factor label="Data sensitivity" level={risk.data_sensitivity} />
        <Factor label="Internet exposure" level={risk.internet_exposure} />
        <span className="text-stone-500">
          Exploitability <strong className="text-stone-800">{risk.exploitability}/5</strong>
        </span>
        <span className="text-stone-500">
          Business impact <strong className="text-stone-800">{risk.business_impact}</strong>
        </span>
      </div>
    </Card>
  );
}

function Factor({ label, level }: { label: string; level: string }) {
  return (
    <span className="flex items-center gap-1.5 text-stone-500">
      {label}
      <Badge level={level} className="text-[10px]" />
    </span>
  );
}
