import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { BoxesIcon, ListIcon, NetworkIcon, SearchIcon, XIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Asset } from "@/lib/types";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { AssetTree } from "@/components/assets/AssetTree";
import { Badge } from "@/components/ui/badge";
import { EmptyState, ErrorState, PageHeader, TableSkeleton } from "@/components/common/states";
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
import { scopeLabel } from "@/lib/scope";

const PAGE_SIZE = 50;

type GroupKey = "none" | "scope" | "resource_type" | "environment";

type View = "list" | "tree";

/**
 * The inventory, and what is worth knowing about each thing in it.
 *
 * Two problems with what this replaces, and the second was a plain bug.
 *
 * The list arrived alphabetically, so the most exposed asset in an estate was
 * wherever the alphabet put it. It now sorts by open findings first, because an
 * asset list in a security product is not a directory -- it is a queue.
 *
 * And the endpoint paginates (`limit`/`offset`, with the true count in `meta`)
 * while the page requested one default-sized page and rendered it as though it
 * were everything. A tenant with four hundred assets saw a hundred, with
 * nothing on the screen suggesting the other three hundred existed.
 *
 * Grouping by scope is the default, because that is how an estate is actually
 * organised and how responsibility for it is usually divided: a resource group
 * tends to have an owner, and "which of my resource groups is the problem" is a
 * question a flat list cannot answer. It is read out of the provider's own id
 * (`lib/scope.ts`) rather than requested, so it costs nothing.
 */
export function AssetsPage() {
  const t = useT();
  const [search, setSearch] = useState("");
  const [environment, setEnvironment] = useState("all");
  const [exposure, setExposure] = useState("all");
  const [type, setType] = useState("all");
  const [groupBy, setGroupBy] = useState<GroupKey>("scope");
  const [view, setView] = useState<View>("list");
  const [page, setPage] = useState(0);

  // The scope filters live in the URL rather than in state: they are arrived
  // at from the tree, which links into this list, so they have to survive
  // being shared and navigated back to.
  const [searchParams, setSearchParams] = useSearchParams();
  const subscriptionId = searchParams.get("subscription_id") ?? "";
  const resourceGroup = searchParams.get("resource_group") ?? "";

  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (environment !== "all") params.set("environment", environment);
  if (exposure !== "all") params.set("exposure", exposure);
  if (type !== "all") params.set("resource_type", type);
  if (subscriptionId) params.set("subscription_id", subscriptionId);
  if (resourceGroup) params.set("resource_group", resourceGroup);
  params.set("limit", String(PAGE_SIZE));
  params.set("offset", String(page * PAGE_SIZE));

  function clearScope() {
    const next = new URLSearchParams(searchParams);
    next.delete("subscription_id");
    next.delete("resource_group");
    setSearchParams(next, { replace: true });
    setPage(0);
  }

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: [
      "assets",
      search,
      environment,
      exposure,
      type,
      subscriptionId,
      resourceGroup,
      page,
    ],
    queryFn: () =>
      api.get<Asset[]>(`/api/v1/assets?${params.toString()}`).then((r) => ({
        assets: r.data,
        total: (r.meta as { total?: number } | undefined)?.total ?? r.data.length,
      })),
    // Paging without this blanks the table on every page turn, which reads as
    // the data having gone rather than as a page loading.
    placeholderData: keepPreviousData,
  });

  // Memoised rather than `data?.assets ?? []`, which minted a new array every
  // render and so defeated both memos below -- they re-sorted and re-grouped
  // the whole page on every keystroke.
  const assets = useMemo(() => data?.assets ?? [], [data]);
  const total = data?.total ?? 0;

  /** Types present in this page, so the filter offers only real options. */
  const types = useMemo(
    () => [...new Set(assets.map((a) => a.resource_type))].sort(),
    [assets],
  );

  const sorted = useMemo(
    () =>
      [...assets].sort((a, b) => {
        // A queue, not a directory: what has findings comes first.
        if (b.open_findings !== a.open_findings) return b.open_findings - a.open_findings;
        return a.name.localeCompare(b.name);
      }),
    [assets],
  );

  const groups = useMemo(() => {
    if (groupBy === "none") return [["", sorted] as const];
    const map = new Map<string, Asset[]>();
    for (const asset of sorted) {
      const key =
        groupBy === "scope"
          ? scopeLabel(asset.provider_resource_id)
          : groupBy === "resource_type"
            ? resourceTypeLabel(asset.resource_type)
            : (asset.environment ?? "Unlabelled");
      map.set(key, [...(map.get(key) ?? []), asset]);
    }
    return [...map.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [sorted, groupBy]);

  const filtering =
    search !== "" ||
    environment !== "all" ||
    exposure !== "all" ||
    type !== "all" ||
    subscriptionId !== "" ||
    resourceGroup !== "";
  const pages = Math.ceil(total / PAGE_SIZE);

  function resetTo(setter: (value: string) => void) {
    return (value: string | null) => {
      setter(value ?? "all");
      // A filter change re-slices the whole set, so page 4 of the old result is
      // meaningless against the new one.
      setPage(0);
    };
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t.assets.title}
        description="Everything CloudGuard has discovered, with what it is worth and how exposed it is."
        actions={
          // Two readings of one inventory: the queue, and the shape. The list
          // ranks by what is wrong; the tree says which part of the estate --
          // and so which owner -- it is wrong in.
          <div className="flex items-center gap-1 rounded-lg border p-0.5">
            <Button
              variant={view === "list" ? "secondary" : "ghost"}
              size="sm"
              onClick={() => setView("list")}
              aria-pressed={view === "list"}
            >
              <ListIcon data-icon="inline-start" />
              List
            </Button>
            <Button
              variant={view === "tree" ? "secondary" : "ghost"}
              size="sm"
              onClick={() => setView("tree")}
              aria-pressed={view === "tree"}
            >
              <NetworkIcon data-icon="inline-start" />
              Hierarchy
            </Button>
          </div>
        }
      />

      {view === "tree" && (
        <>
          <p className="text-xs leading-relaxed text-muted-foreground">
            Counted over the whole estate rather than over a page, and ordered
            worst first at both levels. Opening a group lists what is in it;
            the filters live on the list view.
          </p>
          <AssetTree />
        </>
      )}

      {view === "list" && (
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
        <div className="relative flex-1 lg:max-w-xs">
          <SearchIcon
            className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
            placeholder="Search by name"
            aria-label="Search assets"
            className="pl-8"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <SelectField
            value={type}
            onValueChange={resetTo(setType)}
            ariaLabel="Filter by type"
            className="w-[150px]"
            options={[
              { value: "all", label: "All types" },
              ...types.map((value) => ({
                value,
                label: resourceTypeLabel(value),
              })),
            ]}
          />

          <SelectField
            value={environment}
            onValueChange={resetTo(setEnvironment)}
            ariaLabel="Filter by environment"
            className="w-[160px]"
            options={[
              { value: "all", label: "All environments" },
              { value: "production", label: "Production" },
              { value: "development", label: "Development" },
            ]}
          />

          <SelectField
            value={exposure}
            onValueChange={resetTo(setExposure)}
            ariaLabel="Filter by exposure"
            className="w-[150px]"
            options={[
              { value: "all", label: "All exposure" },
              { value: "CRITICAL", label: "Critical" },
              { value: "HIGH", label: "High" },
              { value: "MEDIUM", label: "Medium" },
              { value: "LOW", label: "Low" },
              { value: "UNKNOWN", label: "Unknown" },
            ]}
          />

          <SelectField
            value={groupBy}
            onValueChange={(value) => setGroupBy((value as GroupKey) || "none")}
            ariaLabel="Group assets"
            className="w-[150px]"
            options={[
              { value: "none", label: "No grouping" },
              { value: "scope", label: "By resource group" },
              { value: "resource_type", label: "By type" },
              { value: "environment", label: "By environment" },
            ]}
          />
        </div>
      </div>
      )}

      {view === "list" && (subscriptionId || resourceGroup) && (
        <div className="flex items-center gap-2">
          <Badge variant="secondary" className="gap-1.5 font-normal">
            {resourceGroup ? (
              <>
                Resource group <code className="font-medium">{resourceGroup}</code>
              </>
            ) : (
              <>
                Subscription <code className="font-medium">{subscriptionId}</code>
              </>
            )}
            <button
              onClick={clearScope}
              aria-label="Clear scope filter"
              className="rounded-full text-muted-foreground transition-colors hover:text-foreground"
            >
              <XIcon className="size-3" />
            </button>
          </Badge>
        </div>
      )}

      {view === "list" && isLoading && <TableSkeleton columns={7} />}

      {view === "list" && error && (
        <ErrorState
          title="Could not load your assets"
          detail="CloudGuard could not reach its own API to read the inventory."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {view === "list" && data && assets.length === 0 && (
        <EmptyState
          icon={BoxesIcon}
          title={filtering ? "No assets match these filters" : t.assets.empty}
          detail={
            filtering
              ? "Widen the filters, or clear the search, to see the rest of the inventory."
              : "Once a scan completes, everything it discovered appears here."
          }
          action={
            filtering ? (
              <Button
                variant="outline"
                onClick={() => {
                  setSearch("");
                  setEnvironment("all");
                  setExposure("all");
                  setType("all");
                  clearScope();
                  setPage(0);
                }}
              >
                Clear filters
              </Button>
            ) : (
              <Link
                to="/scans"
                className={buttonVariants({ variant: "outline" })}
              >
                Run a scan
              </Link>
            )
          }
        />
      )}

      {view === "list" && data && assets.length > 0 && (
        <>
          <Card className="overflow-hidden py-0">
            <CardContent className="px-0">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="w-[30%]">Resource</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Environment</TableHead>
                    <TableHead>Criticality</TableHead>
                    <TableHead>Exposure</TableHead>
                    <TableHead className="text-right">{t.assets.openFindings}</TableHead>
                    <TableHead className="text-right">Last seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {groups.map(([groupName, rows]) => (
                    <>
                      {groupName && (
                        <TableRow key={`group-${groupName}`} className="hover:bg-transparent">
                          <TableCell
                            colSpan={7}
                            className="bg-muted/50 py-1.5 text-xs font-medium text-muted-foreground"
                          >
                            {groupName}
                            <span className="ml-2 tabular-nums opacity-70">{rows.length}</span>
                          </TableCell>
                        </TableRow>
                      )}
                      {rows.map((asset) => (
                        <TableRow key={asset.id}>
                          <TableCell className="max-w-0">
                            <Link
                              to={`/assets/${asset.id}`}
                              className="block truncate font-medium text-foreground hover:underline"
                            >
                              {asset.name}
                            </Link>
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {resourceTypeLabel(asset.resource_type)}
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {asset.environment ?? "—"}
                          </TableCell>
                          <TableCell>
                            <SeverityBadge level={asset.criticality} size="sm" />
                          </TableCell>
                          <TableCell>
                            <SeverityBadge level={asset.public_exposure} size="sm" />
                          </TableCell>
                          <TableCell className="text-right">
                            <span
                              className={cn(
                                "font-medium tabular-nums",
                                asset.open_findings === 0 && "text-muted-foreground",
                              )}
                            >
                              {asset.open_findings}
                            </span>
                          </TableCell>
                          <TableCell className="text-right text-muted-foreground">
                            {formatDate(asset.last_seen_at)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-muted-foreground">
              {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + assets.length} of {total} asset
              {total === 1 ? "" : "s"}
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
