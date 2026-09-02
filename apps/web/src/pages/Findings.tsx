import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ArrowDownIcon, SearchIcon, ShieldCheckIcon, XIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { RiskScore } from "@/components/security/SecurityScore";
import {
  EmptyState,
  ErrorState,
  PageHeader,
  TableSkeleton,
} from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { SelectField } from "@/components/common/SelectField";
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
const PAGE_SIZE = 50;
const SEARCH_DEBOUNCE_MS = 250;

type SortKey = "risk" | "severity" | "recent";

/**
 * The list a security engineer actually works from.
 *
 * **The bug this page had was silent, which is what made it serious.** It asked
 * for findings with no `limit`, took the API's default hundred, and rendered
 * them as though they were all of them -- so a tenant with four hundred
 * findings saw a hundred with nothing on screen saying so. Search and sort then
 * ran over that hundred in the browser, which turned a display problem into a
 * false negative: searching an estate and being told "no findings match" when
 * three hundred rows were never in the browser to match against.
 *
 * So both moved to the database (`GET /findings?search=&sort=`), and the page
 * pages properly. The cost is a round trip per keystroke, which the debounce
 * below pays for; the alternative was a security product answering questions
 * about data it did not have.
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
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [sort, setSort] = useState<SortKey>("risk");
  const [page, setPage] = useState(0);

  // A request per keystroke would be six for "public"; a request per pause is
  // one. The delay is short enough that a reader who stops typing to look at
  // the screen has results by the time their eyes arrive.
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(0);
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [search]);

  // The rule filter lives in the URL rather than in state: it is arrived at
  // from elsewhere — a compliance control's evidence list, a rule page — so it
  // has to survive being linked to, shared, and navigated back to.
  const [searchParams, setSearchParams] = useSearchParams();
  const ruleId = searchParams.get("rule_id") ?? "";
  // Seeded from the URL rather than fixed at OPEN, and read through the router
  // rather than off `window.location` -- the second is empty under a
  // MemoryRouter and wrong under any router that has navigated.
  //
  // A link that scopes the list to one reading arrives asking "what rested on
  // this", and the honest answer includes the findings that reading raised and
  // somebody has since fixed. Defaulting to OPEN would land that link on an
  // empty table, which reads as "nothing rested on it".
  const [status, setStatus] = useState(
    () => searchParams.get("status") ?? "OPEN",
  );
  // Arrived from a reading on the scans page: "what rests on this". Filtered on
  // the reading rather than its key, so the count that was clicked and the rows
  // that come back are the same set.
  const evidenceId = searchParams.get("evidence_id") ?? "";

  const params = new URLSearchParams();
  if (severity !== "all") params.set("severity", severity);
  if (status !== "all") params.set("status", status);
  if (ruleId) params.set("rule_id", ruleId);
  if (evidenceId) params.set("evidence_id", evidenceId);
  if (debouncedSearch.trim()) params.set("search", debouncedSearch.trim());
  params.set("sort", sort);
  params.set("limit", String(PAGE_SIZE));
  params.set("offset", String(page * PAGE_SIZE));

  /**
   * Drop one or more scoping filters in a single write.
   *
   * Variadic rather than called twice: each call builds its next value from the
   * unchanged `searchParams`, so two in a row would have the second put back
   * what the first removed -- "Clear filters" leaving a chip on screen.
   */
  function clearParamFilters(...names: string[]) {
    const next = new URLSearchParams(searchParams);
    for (const name of names) next.delete(name);
    setSearchParams(next, { replace: true });
    setPage(0);
  }

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: [
      "findings",
      severity,
      status,
      ruleId,
      evidenceId,
      debouncedSearch,
      sort,
      page,
    ],
    queryFn: () =>
      api.get<Finding[]>(`/api/v1/findings?${params.toString()}`).then((r) => ({
        findings: r.data,
        total:
          (r.meta as { total?: number } | undefined)?.total ?? r.data.length,
      })),
    // Without this the table blanks on every page turn, which reads as the
    // findings having gone rather than as a page loading.
    placeholderData: keepPreviousData,
  });

  // Already filtered and ordered by the database; the page renders what it was
  // sent rather than re-deciding it.
  const rows = data?.findings ?? [];
  const total = data?.total ?? 0;
  const pages = Math.ceil(total / PAGE_SIZE);

  const filtered =
    search.trim().length > 0 ||
    severity !== "all" ||
    status !== "OPEN" ||
    !!ruleId ||
    !!evidenceId;

  /** Any filter change re-slices the set, so page 4 of the old one is meaningless. */
  function refilter(apply: () => void) {
    apply();
    setPage(0);
  }

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
          <SelectField
            value={severity}
            onValueChange={(value) => refilter(() => setSeverity(value || "all"))}
            ariaLabel="Filter by severity"
            className="w-[150px]"
            options={[
              { value: "all", label: "All severities" },
              ...SEVERITIES.map((level) => ({
                value: level,
                label: level.charAt(0) + level.slice(1).toLowerCase(),
              })),
            ]}
          />

          <SelectField
            value={status}
            onValueChange={(value) => refilter(() => setStatus(value || "all"))}
            ariaLabel="Filter by status"
            className="w-[160px]"
            options={[
              { value: "all", label: "All statuses" },
              { value: "OPEN", label: "Open" },
              { value: "IN_PROGRESS", label: "In progress" },
              { value: "RESOLVED", label: "Verified fixed" },
              { value: "ACCEPTED_RISK", label: "Risk accepted" },
            ]}
          />
        </div>
      </div>

      {(ruleId || evidenceId) && (
        <div className="flex flex-wrap items-center gap-2">
          {ruleId && (
            <Badge variant="secondary" className="gap-1.5 font-normal">
              Rule <code className="font-medium">{ruleId}</code>
              <button
                onClick={() => clearParamFilters("rule_id")}
                aria-label="Clear rule filter"
                className="rounded-full text-muted-foreground transition-colors hover:text-foreground"
              >
                <XIcon className="size-3" />
              </button>
            </Badge>
          )}
          {evidenceId && (
            // Named for what it means rather than for the column: nobody
            // arrived here thinking about an evidence id, they clicked a
            // listing on a scan.
            <Badge variant="secondary" className="gap-1.5 font-normal">
              {t.findings.restingOnReading}
              <button
                onClick={() => clearParamFilters("evidence_id")}
                aria-label="Clear evidence filter"
                className="rounded-full text-muted-foreground transition-colors hover:text-foreground"
              >
                <XIcon className="size-3" />
              </button>
            </Badge>
          )}
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
          title={
            filtered ? "No findings match these filters" : t.findings.empty
          }
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
                  // Both scoping filters, or "Clear filters" would leave the
                  // reader on an empty table with a chip still narrowing it.
                  clearParamFilters("rule_id", "evidence_id");
                }}
              >
                Clear filters
              </Button>
            ) : (
              <Link
                to="/scans"
                className={buttonVariants({ variant: "outline" })}
              >
                View scan coverage
              </Link>
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
                    <SortableHead
                      label={t.common.severity}
                      sortKey="severity"
                      active={sort}
                      onSort={(key) => refilter(() => setSort(key))}
                    />
                    <TableHead>{t.findings.asset}</TableHead>
                    <SortableHead
                      label={t.findings.riskScore}
                      sortKey="risk"
                      active={sort}
                      align="right"
                      onSort={(key) => refilter(() => setSort(key))}
                    />
                    <TableHead>{t.common.status}</TableHead>
                    <SortableHead
                      label={t.findings.lastSeen}
                      sortKey="recent"
                      active={sort}
                      align="right"
                      onSort={(key) => refilter(() => setSort(key))}
                    />
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
                              {resourceTypeLabel(
                                finding.resource.resource_type,
                              )}
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

          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-muted-foreground">
              {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + rows.length} of {total}{" "}
              finding
              {total === 1 ? "" : "s"}
              {filtered ? " matching these filters" : ""}
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
 * A column that is also the way to order by it.
 *
 * Ordering used to live in a fourth dropdown beside the filters, which put the
 * control somewhere other than the thing it acts on and left the table's own
 * headers inert -- so the obvious gesture, clicking "Risk score", did nothing.
 *
 * One direction per column, not a toggle, because the backend orders each of
 * these the only way that is useful: worst risk, worst severity and most
 * recent all mean descending, and an ascending findings table would put the
 * least urgent row at the top of a security queue.
 */
function SortableHead({
  label,
  sortKey,
  active,
  align = "left",
  onSort,
}: {
  label: string;
  sortKey: SortKey;
  active: SortKey;
  align?: "left" | "right";
  onSort: (key: SortKey) => void;
}) {
  const isActive = active === sortKey;
  return (
    <TableHead
      aria-sort={isActive ? "descending" : "none"}
      className={align === "right" ? "text-right" : undefined}
    >
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        aria-label={`Sort by ${label.toLowerCase()}`}
        className={cn(
          "inline-flex items-center gap-1 rounded-sm transition-colors hover:text-foreground",
          "focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
          align === "right" && "flex-row-reverse",
          isActive && "text-foreground",
        )}
      >
        {label}
        <ArrowDownIcon
          className={cn(
            "size-3 transition-opacity",
            isActive ? "opacity-100" : "opacity-0",
          )}
          aria-hidden
        />
      </button>
    </TableHead>
  );
}
