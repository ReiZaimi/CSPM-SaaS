import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArchiveIcon, ListChecksIcon, SearchIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Rule } from "@/lib/types";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { RemediationPanel } from "@/components/security/RemediationPanel";
import { cn, formatEffort, resourceTypeLabel } from "@/lib/format";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

/**
 * Every check CloudGuard runs.
 *
 * Filtered in the browser, and that is not the compromise it would be
 * elsewhere: the catalogue is the product's own rulebook, it arrives whole in
 * one request, and it is dozens of entries rather than an estate's worth. There
 * is nothing here that a search could fail to see.
 */
export function RulesPage() {
  const t = useT();
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [showWithdrawn, setShowWithdrawn] = useState(false);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["rules"],
    queryFn: () => api.get<Rule[]>("/api/v1/rules").then((r) => r.data),
  });

  // Counted over everything the API returned, not over the filtered list: the
  // toggle has to say how many rules it would reveal, which is a fact about
  // the catalogue rather than about the current search.
  const withdrawnCount = useMemo(
    () => (data ?? []).filter((rule) => !rule.enabled).length,
    [data],
  );

  const rules = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (data ?? []).filter((rule) => {
      // A withdrawn rule no longer runs. Listing it beside the live ones under
      // a heading that says "every check CloudGuard runs" overstated what is
      // being checked, so it is out unless asked for.
      if (!rule.enabled && !showWithdrawn) return false;
      if (severity !== "all" && rule.severity !== severity) return false;
      if (!needle) return true;
      return `${rule.name} ${rule.rule_id} ${rule.description} ${rule.category}`
        .toLowerCase()
        .includes(needle);
    });
  }, [data, search, severity, showWithdrawn]);

  const live = (data ?? []).length - withdrawnCount;
  const filtering = search.trim().length > 0 || severity !== "all";

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t.rules.title}
        description="Every check CloudGuard runs. Rules are deterministic — the same environment always produces the same result."
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
            placeholder="Search rules"
            aria-label="Search rules"
            className="pl-8"
          />
        </div>
        <Select value={severity} onValueChange={(v) => setSeverity(v ?? "all")}>
          <SelectTrigger
            size="sm"
            className="w-[150px]"
            aria-label="Filter by severity"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            {SEVERITIES.map((value) => (
              <SelectItem key={value} value={value}>
                {value.charAt(0) + value.slice(1).toLowerCase()}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {/* Offered only when there is something to reveal. A permanent toggle
            on a catalogue with nothing withdrawn implies rules are missing. */}
        {withdrawnCount > 0 && (
          <Button
            variant="outline"
            size="sm"
            aria-pressed={showWithdrawn}
            onClick={() => setShowWithdrawn((v) => !v)}
          >
            <ArchiveIcon className="size-4" aria-hidden />
            {showWithdrawn ? t.rules.hideWithdrawn : t.rules.showWithdrawn}
            {!showWithdrawn && ` (${withdrawnCount})`}
          </Button>
        )}
      </div>

      {isLoading && <CardsSkeleton />}

      {error && (
        <ErrorState
          title="Could not load the rule catalogue"
          detail="CloudGuard could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && rules.length === 0 && (
        <EmptyState
          icon={ListChecksIcon}
          title={filtering ? "No rules match" : t.rules.empty}
          detail={
            filtering
              ? "Widen the filters to see the rest of the catalogue."
              : undefined
          }
          action={
            filtering ? (
              <Button
                variant="outline"
                onClick={() => {
                  setSearch("");
                  setSeverity("all");
                }}
              >
                Clear filters
              </Button>
            ) : undefined
          }
        />
      )}

      {rules.length > 0 && (
        <>
          <div className="flex flex-col gap-3">
            {rules.map((rule) => (
              <RuleCard key={rule.rule_id} rule={rule} />
            ))}
          </div>
          <p className="text-xs text-muted-foreground">
            {rules.length} of {live} rule{live === 1 ? "" : "s"} CloudGuard runs
            {withdrawnCount > 0 && `, and ${withdrawnCount} ${t.rules.withdrawnCount}`}
          </p>
        </>
      )}
    </div>
  );
}

function RuleCard({ rule }: { rule: Rule }) {
  const t = useT();
  const [open, setOpen] = useState(false);

  return (
    <Card className={cn(!rule.enabled && "border-dashed")}>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge level={rule.severity} />
          <code className="text-xs text-muted-foreground">{rule.rule_id}</code>
          <span className="text-xs text-muted-foreground">v{rule.version}</span>
          {/* A tenant-wide rule is about the directory rather than any one
              resource, which is why nothing in the asset list carries it. */}
          {rule.scope === "aggregate" && (
            <Badge variant="secondary">Tenant-wide</Badge>
          )}
          {/* Dashed and named rather than greyed. A rule that has stopped
              running is not a quieter rule -- it is one whose severity below
              describes what it used to check. */}
          {!rule.enabled && (
            <span className="inline-flex items-center rounded-full border border-dashed border-unknown-border bg-unknown-bg px-2 py-0.5 text-xs font-medium text-unknown">
              {t.rules.withdrawn}
            </span>
          )}
        </div>
        <CardTitle className="text-sm">{rule.name}</CardTitle>
      </CardHeader>

      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <p className="max-w-3xl flex-1 text-sm text-muted-foreground">
            {rule.description}
          </p>
          <div className="shrink-0 text-right text-xs text-muted-foreground">
            <p>Exploitability {rule.exploitability}/5</p>
            <p className="mt-0.5">
              {formatEffort(rule.estimated_effort_minutes)} to fix
            </p>
          </div>
        </div>

        {!rule.enabled && (
          <p className="rounded-lg border border-dashed border-unknown-border bg-unknown-bg px-3 py-2 text-xs leading-relaxed text-foreground">
            {t.rules.withdrawnHelp}
          </p>
        )}

        {/* Everything the catalogue held and never showed. Behind a toggle
            rather than always open: a page of forty rules each carrying its
            rationale and four fix formats is a document, not a list. */}
        <div>
          <Button
            variant="ghost"
            size="sm"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? t.rules.hideDetail : t.rules.showDetail}
          </Button>
        </div>

        {open && (
          <div className="flex flex-col gap-4">
            {rule.rationale && (
              <div className="rounded-lg border bg-muted/40 p-3">
                <p className="text-xs font-medium text-muted-foreground">
                  {t.rules.why}
                </p>
                <p className="mt-1 text-sm leading-relaxed text-foreground">
                  {rule.rationale}
                </p>
              </div>
            )}
            <RemediationPanel
              remediation={rule.remediation}
              spec={rule.remediation_spec}
              effortMinutes={rule.estimated_effort_minutes}
            />
          </div>
        )}
      </CardContent>

      <CardFooter className="flex flex-wrap gap-x-6 gap-y-2 border-t pt-4 text-xs">
        {rule.applies_to.length > 0 && (
          <span className="text-muted-foreground">
            Applies to{" "}
            <strong className="text-foreground">
              {rule.applies_to.map(resourceTypeLabel).join(", ")}
            </strong>
          </span>
        )}
        {Object.entries(rule.compliance_mappings).map(
          ([framework, controls]) => (
            <span key={framework} className="text-muted-foreground">
              {framework.replace(/_/g, " ")}{" "}
              <strong className="text-foreground">{controls.join(", ")}</strong>
            </span>
          ),
        )}
      </CardFooter>
    </Card>
  );
}
