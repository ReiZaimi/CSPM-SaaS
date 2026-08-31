import { useEffect, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { RadarIcon, SearchIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Risk } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
} from "@/components/ui/card";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const PAGE_SIZE = 25;
const SEARCH_DEBOUNCE_MS = 250;

/**
 * What the findings mean, ranked.
 *
 * This page had the same silent truncation the findings list had: it asked for
 * risks with no `limit`, took the API's default hundred and rendered them as
 * the whole set. On a page whose entire claim is "these are your worst
 * problems, in order", showing the first hundred of four hundred is not a
 * display bug -- it is the wrong answer to the only question being asked.
 *
 * It also had no filters at all, on a list that mixes two kinds of thing and
 * four levels. Everything offered here is filtered by the database, so a filter
 * narrows the estate rather than the page.
 */
export function RisksPage() {
  const t = useT();
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [level, setLevel] = useState("all");
  const [status, setStatus] = useState("all");
  const [kind, setKind] = useState("all");
  const [page, setPage] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(0);
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [search]);

  const params = new URLSearchParams();
  if (debouncedSearch.trim()) params.set("search", debouncedSearch.trim());
  if (level !== "all") params.set("risk_level", level);
  if (status !== "all") params.set("status", status);
  if (kind !== "all") params.set("kind", kind);
  params.set("limit", String(PAGE_SIZE));
  params.set("offset", String(page * PAGE_SIZE));

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["risks", debouncedSearch, level, status, kind, page],
    queryFn: () =>
      api.get<Risk[]>(`/api/v1/risks?${params.toString()}`).then((r) => ({
        risks: r.data,
        total:
          (r.meta as { total?: number } | undefined)?.total ?? r.data.length,
      })),
    placeholderData: keepPreviousData,
  });

  const risks = data?.risks ?? [];
  const total = data?.total ?? 0;
  const pages = Math.ceil(total / PAGE_SIZE);
  const filtering =
    search.trim().length > 0 ||
    level !== "all" ||
    status !== "all" ||
    kind !== "all";

  function refilter(apply: () => void) {
    apply();
    setPage(0);
  }

  function clearFilters() {
    setSearch("");
    setLevel("all");
    setStatus("all");
    setKind("all");
    setPage(0);
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t.risks.title}
        description="A finding is what we observed. A risk is what it means for this asset, with this data, at this level of exposure."
      />

      <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
        <div className="relative flex-1 lg:max-w-xs">
          <SearchIcon
            className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search risks"
            aria-label="Search risks"
            className="pl-8"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Select
            value={level}
            onValueChange={(v) => refilter(() => setLevel(v ?? "all"))}
          >
            <SelectTrigger
              size="sm"
              className="w-[150px]"
              aria-label="Filter by risk level"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All levels</SelectItem>
              <SelectItem value="CRITICAL">Critical</SelectItem>
              <SelectItem value="HIGH">High</SelectItem>
              <SelectItem value="MEDIUM">Medium</SelectItem>
              <SelectItem value="LOW">Low</SelectItem>
              {/* UNKNOWN is a level the risk engine really assigns, and
                  leaving it out of the filter would hide the risks CloudGuard
                  could not score -- the ones most worth looking at. */}
              <SelectItem value="UNKNOWN">Unknown</SelectItem>
            </SelectContent>
          </Select>

          <Select
            value={status}
            onValueChange={(v) => refilter(() => setStatus(v ?? "all"))}
          >
            <SelectTrigger
              size="sm"
              className="w-[160px]"
              aria-label="Filter by status"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="OPEN">Open</SelectItem>
              <SelectItem value="IN_PROGRESS">In progress</SelectItem>
              <SelectItem value="ACCEPTED">Accepted</SelectItem>
              <SelectItem value="RESOLVED">Resolved</SelectItem>
            </SelectContent>
          </Select>

          <Select
            value={kind}
            onValueChange={(v) => refilter(() => setKind(v ?? "all"))}
          >
            <SelectTrigger
              size="sm"
              className="w-[150px]"
              aria-label="Filter by kind"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Findings and routes</SelectItem>
              <SelectItem value="FINDING">Findings only</SelectItem>
              <SelectItem value="ATTACK_PATH">Attack paths</SelectItem>
              <SelectItem value="ESCALATION">Escalations</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {isLoading && <CardsSkeleton />}

      {error && (
        <ErrorState
          title="Could not load your risks"
          detail="CloudGuard could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && risks.length === 0 && (
        <EmptyState
          icon={RadarIcon}
          title={filtering ? "No risks match these filters" : t.risks.empty}
          detail={
            filtering
              ? "Widen the filters, or clear the search, to see the rest of the ranking."
              : undefined
          }
          action={
            filtering ? (
              <Button variant="outline" onClick={clearFilters}>
                Clear filters
              </Button>
            ) : undefined
          }
        />
      )}

      {data && risks.length > 0 && (
        <>
          <div className="flex flex-col gap-3">
            {/* Both kinds in one list, deliberately. A route outranking the
                findings inside it is only visible where they are ranked
                together — on a page of its own it would be a second opinion
                nobody compares. The kind filter can separate them; the default
                does not. */}
            {risks.map((risk) =>
              risk.kind === "FINDING" ? (
                <FindingRiskCard key={risk.id} risk={risk} />
              ) : (
                <ScenarioCard key={risk.id} risk={risk} />
              ),
            )}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-muted-foreground">
              {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + risks.length} of{" "}
              {total} risk
              {total === 1 ? "" : "s"}
              {filtering ? " matching these filters" : ""}
            </p>
            {pages > 1 && (
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page === 0}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                >
                  Previous
                </Button>
                <span className="text-xs tabular-nums text-muted-foreground">
                  {page + 1} / {pages}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page + 1 >= pages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </Button>
              </div>
            )}
          </div>
        </>
      )}
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
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge level={risk.risk_level} />
              <StatusPill status={risk.status} />
              {/* Says which formula scored this, so the arithmetic below is
                  read against the right one. */}
              <Badge variant="outline">
                {escalation ? t.risks.escalationBadge : t.risks.scenarioBadge}
              </Badge>
            </div>
            <Link
              to={`/risks/${risk.id}`}
              className="mt-2 block text-sm font-medium text-foreground underline-offset-4 hover:underline"
            >
              {risk.title}
            </Link>
            <p className="mt-1 text-xs text-muted-foreground">
              {escalation ? t.risks.escalationIntro : t.risks.scenarioIntro}
            </p>
          </div>
          <div className="shrink-0 text-right">
            <p className="text-3xl font-semibold tabular-nums text-foreground">
              {Number(risk.risk_score).toFixed(0)}
            </p>
            <p className="text-xs text-muted-foreground">risk score</p>
          </div>
        </div>
      </CardHeader>

      {risk.path.length > 0 && (
        <CardContent className="border-t pt-3">
          <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
            {t.risks.routeLabel}
          </p>
          <ol className="mt-2 flex flex-col gap-1.5">
            {risk.path.map((step, index) => (
              <li
                key={`${step.source_id}-${step.relationship}-${step.target_id}`}
                className="flex items-start gap-2.5 text-sm text-muted-foreground"
              >
                <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border bg-background text-[10px] font-medium text-muted-foreground">
                  {index + 1}
                </span>
                {step.description}
              </li>
            ))}
          </ol>
        </CardContent>
      )}

      {/* The arithmetic, in the terms the score was actually built from. A
          customer asking why this outranks the finding inside it gets the
          answer rather than a number. */}
      <CardFooter className="flex flex-wrap gap-x-6 gap-y-2 border-t pt-4 text-xs">
        <span className="text-muted-foreground">
          {t.risks.worstMember}{" "}
          <strong className="text-foreground">
            {breakdown.worst_member ?? "—"}
          </strong>
        </span>
        <span className="text-muted-foreground">
          {t.risks.amplifier}{" "}
          <strong className="text-foreground">
            +{breakdown.amplifier ?? 0}
          </strong>
        </span>
        <span className="text-muted-foreground">
          Hops{" "}
          <strong className="text-foreground">
            {breakdown.hops ?? risk.path.length}
          </strong>
        </span>
        {capped && (
          <span className="text-muted-foreground">{t.risks.cappedNote}</span>
        )}
      </CardFooter>
    </Card>
  );
}

function FindingRiskCard({ risk }: { risk: Risk }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <SeverityBadge level={risk.risk_level} />
              <StatusPill status={risk.status} />
            </div>
            <Link
              to={`/risks/${risk.id}`}
              className="mt-2 block text-sm font-medium text-foreground underline-offset-4 hover:underline"
            >
              {risk.title}
            </Link>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              {risk.description}
            </p>
          </div>
          <div className="shrink-0 text-right">
            <p className="text-3xl font-semibold tabular-nums text-foreground">
              {Number(risk.risk_score).toFixed(0)}
            </p>
            <p className="text-xs text-muted-foreground">risk score</p>
          </div>
        </div>
      </CardHeader>

      <CardFooter className="flex flex-wrap gap-x-6 gap-y-2 border-t pt-4 text-xs">
        <Factor label="Asset criticality" level={risk.asset_criticality} />
        <Factor label="Data sensitivity" level={risk.data_sensitivity} />
        <Factor label="Internet exposure" level={risk.internet_exposure} />
        <span className="text-muted-foreground">
          Exploitability{" "}
          <strong className="text-foreground">{risk.exploitability}/5</strong>
        </span>
        <span className="text-muted-foreground">
          Business impact{" "}
          <strong className="text-foreground">{risk.business_impact}</strong>
        </span>
      </CardFooter>
    </Card>
  );
}

function Factor({ label, level }: { label: string; level: string }) {
  return (
    <span className="flex items-center gap-1.5 text-muted-foreground">
      {label}
      <SeverityBadge level={level} size="sm" />
    </span>
  );
}
