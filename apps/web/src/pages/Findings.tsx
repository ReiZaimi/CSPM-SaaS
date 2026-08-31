import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { SearchIcon, ShieldCheckIcon, XIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/ui";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { RiskScore } from "@/components/security/SecurityScore";
import { EmptyState, ErrorState, PageHeader, TableSkeleton } from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn, formatDate, resourceTypeLabel } from "@/lib/format";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

/** Severity as a rank, so "worst first" is a comparison rather than a lookup. */
const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  UNKNOWN: 4,
};

type SortKey = "risk" | "severity" | "recent";

/**
 * The list a security engineer actually works from.
 *
 * Two things were missing and both cost real time. There was no search, so
 * finding the one storage account somebody had asked about meant reading every
 * row; and there was no ordering, so the list arrived in whatever order the API
 * returned and the most dangerous finding could be anywhere in it.
 *
 * Sorting defaults to risk rather than severity, deliberately. Severity is what
 * the *rule* says in the abstract; risk is what it means on this asset, with
 * this data, at this exposure -- and a HIGH on a production database outranks a
 * CRITICAL on an isolated sandbox. Severity remains available for the reader
 * who wants the rulebook's own order.
 */
export function FindingsPage() {
  const t = useT();
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("OPEN");
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<SortKey>("risk");

  // The rule filter lives in the URL rather than in state: it is arrived at
  // from elsewhere — a compliance control's evidence list, a rule page — so it
  // has to survive being linked to, shared, and navigated back to.
  const [searchParams, setSearchParams] = useSearchParams();
  const ruleId = searchParams.get("rule_id") ?? "";

  const params = new URLSearchParams();
  if (severity !== "all") params.set("severity", severity);
  if (status !== "all") params.set("status", status);
  if (ruleId) params.set("rule_id", ruleId);

  function clearRuleFilter() {
    const next = new URLSearchParams(searchParams);
    next.delete("rule_id");
    setSearchParams(next, { replace: true });
  }

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["findings", severity, status, ruleId],
    queryFn: () =>
      api.get<Finding[]>(`/api/v1/findings?${params.toString()}`).then((r) => r.data),
  });

  /**
   * Search and sort happen here rather than on the server.
   *
   * The findings endpoint filters by severity, status and rule and does not
   * take a query or an order. Sorting client-side is honest for a list this
   * size and avoids a backend change for a UI improvement — but it is a
   * limitation worth naming: it orders *the page it was given*, so it will need
   * to move server-side the day this endpoint paginates.
   */
  const rows = useMemo(() => {
    if (!data) return [];
    const needle = search.trim().toLowerCase();
    const filtered = needle
      ? data.filter(
          (f) =>
            f.title.toLowerCase().includes(needle) ||
            f.rule_id.toLowerCase().includes(needle) ||
            (f.resource?.name ?? "").toLowerCase().includes(needle),
        )
      : data;

    return [...filtered].sort((a, b) => {
      if (sort === "severity") {
        const bySeverity =
          (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);
        if (bySeverity !== 0) return bySeverity;
      }
      if (sort === "recent") {
        return (
          new Date(b.last_detected_at).getTime() - new Date(a.last_detected_at).getTime()
        );
      }
      return Number(b.risk_score ?? 0) - Number(a.risk_score ?? 0);
    });
  }, [data, search, sort]);

  const filtered = search.trim().length > 0 || severity !== "all" || status !== "OPEN" || !!ruleId;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t.findings.title}
        description="Everything CloudGuard has observed and judged wrong, ranked by what it means on the asset it was found on."
      />

      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1 sm:max-w-xs">
          <SearchIcon
            className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search findings, rules or assets"
            aria-label="Search findings"
            className="pl-8"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Select value={severity} onValueChange={(v) => setSeverity(v ?? "all")}>
            <SelectTrigger size="sm" className="w-[150px]" aria-label="Filter by severity">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All severities</SelectItem>
              {SEVERITIES.map((s) => (
                <SelectItem key={s} value={s}>
                  {s.charAt(0) + s.slice(1).toLowerCase()}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={status} onValueChange={(v) => setStatus(v ?? "all")}>
            <SelectTrigger size="sm" className="w-[160px]" aria-label="Filter by status">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="OPEN">Open</SelectItem>
              <SelectItem value="IN_PROGRESS">In progress</SelectItem>
              <SelectItem value="RESOLVED">Verified fixed</SelectItem>
              <SelectItem value="ACCEPTED_RISK">Risk accepted</SelectItem>
            </SelectContent>
          </Select>

          <Select value={sort} onValueChange={(v) => setSort((v as SortKey) ?? "risk")}>
            <SelectTrigger size="sm" className="w-[150px]" aria-label="Sort findings">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="risk">Highest risk</SelectItem>
              <SelectItem value="severity">Severity</SelectItem>
              <SelectItem value="recent">Most recent</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {ruleId && (
        <div className="flex items-center gap-2">
          <Badge variant="secondary" className="gap-1.5 font-normal">
            Rule <code className="font-medium">{ruleId}</code>
            <button
              onClick={clearRuleFilter}
              aria-label="Clear rule filter"
              className="rounded-full text-muted-foreground transition-colors hover:text-foreground"
            >
              <XIcon className="size-3" />
            </button>
          </Badge>
        </div>
      )}

      {isLoading && <TableSkeleton columns={6} />}

      {error && (
        <ErrorState
          title="Could not load findings"
          detail="CloudGuard could not reach its own API to read your findings."
          impact="This is a problem loading the page, not a change in your security posture — nothing about your environment has been reassessed."
          onRetry={() => refetch()}
        />
      )}

      {data && rows.length === 0 && (
        <EmptyState
          icon={ShieldCheckIcon}
          title={filtered ? "No findings match these filters" : t.findings.empty}
          detail={
            filtered
              ? "Widen the filters, or clear the search, to see the rest of this environment."
              : "Your latest scan reached a verdict on every check it could run and raised nothing. Coverage gaps, if any, are shown on the scan."
          }
          action={
            filtered ? (
              <Button
                variant="outline"
                onClick={() => {
                  setSearch("");
                  setSeverity("all");
                  setStatus("OPEN");
                  clearRuleFilter();
                }}
              >
                Clear filters
              </Button>
            ) : (
              <Button variant="outline" render={<Link to="/scans" />}>
                View scan coverage
              </Button>
            )
          }
        />
      )}

      {data && rows.length > 0 && (
        <>
          <Card className="overflow-hidden py-0">
            <CardContent className="px-0">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="w-[45%]">Finding</TableHead>
                    <TableHead>{t.common.severity}</TableHead>
                    <TableHead>{t.findings.asset}</TableHead>
                    <TableHead className="text-right">{t.findings.riskScore}</TableHead>
                    <TableHead>{t.common.status}</TableHead>
                    <TableHead className="text-right">{t.findings.lastSeen}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((finding) => (
                    <TableRow key={finding.id} className="group">
                      <TableCell className="max-w-0">
                        <Link
                          to={`/findings/${finding.id}`}
                          className="block truncate font-medium text-foreground after:absolute hover:underline"
                        >
                          {finding.title}
                        </Link>
                        <p className="mt-0.5 truncate text-xs text-muted-foreground">
                          {finding.rule_id}
                        </p>
                      </TableCell>
                      <TableCell>
                        <SeverityBadge level={finding.severity} />
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {finding.resource ? (
                          <>
                            <span className="block max-w-[16rem] truncate text-foreground">
                              {finding.resource.name}
                            </span>
                            <span className="text-xs">
                              {resourceTypeLabel(finding.resource.resource_type)}
                            </span>
                          </>
                        ) : (
                          <span className="italic">Tenant-wide</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <RiskScore score={finding.risk_score} />
                      </TableCell>
                      <TableCell>
                        <StatusPill status={finding.status} />
                      </TableCell>
                      <TableCell className="text-right text-muted-foreground">
                        {formatDate(finding.last_detected_at)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <p className={cn("text-xs text-muted-foreground")}>
            {rows.length} of {data.length} finding{data.length === 1 ? "" : "s"}
            {filtered ? " matching these filters" : ""}
          </p>
        </>
      )}
    </div>
  );
}
