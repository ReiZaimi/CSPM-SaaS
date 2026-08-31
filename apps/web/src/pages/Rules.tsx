import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ListChecksIcon, SearchIcon } from "lucide-react";

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
import { formatEffort, resourceTypeLabel } from "@/lib/format";

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

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["rules"],
    queryFn: () => api.get<Rule[]>("/api/v1/rules").then((r) => r.data),
  });

  const rules = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (data ?? []).filter((rule) => {
      if (severity !== "all" && rule.severity !== severity) return false;
      if (!needle) return true;
      return `${rule.name} ${rule.rule_id} ${rule.description} ${rule.category}`
        .toLowerCase()
        .includes(needle);
    });
  }, [data, search, severity]);

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
            {rules.length} of {data?.length ?? 0} rule
            {data?.length === 1 ? "" : "s"}
          </p>
        </>
      )}
    </div>
  );
}

function RuleCard({ rule }: { rule: Rule }) {
  return (
    <Card>
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
        </div>
        <CardTitle className="text-sm">{rule.name}</CardTitle>
      </CardHeader>

      <CardContent className="flex flex-wrap items-start justify-between gap-4">
        <p className="max-w-3xl flex-1 text-sm text-muted-foreground">
          {rule.description}
        </p>
        <div className="shrink-0 text-right text-xs text-muted-foreground">
          <p>Exploitability {rule.exploitability}/5</p>
          <p className="mt-0.5">
            {formatEffort(rule.estimated_effort_minutes)} to fix
          </p>
        </div>
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
