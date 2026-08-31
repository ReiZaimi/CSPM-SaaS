import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { BoxesIcon, SearchIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Asset } from "@/lib/types";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { EmptyState, ErrorState, PageHeader, TableSkeleton } from "@/components/common/states";
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

const PAGE_SIZE = 50;

type GroupKey = "none" | "resource_type" | "environment";

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
 * **Known API limitation.** `GET /assets` does not return
 * `provider_resource_id`, so the subscription/resource-group hierarchy cannot
 * be derived here -- the ARM id is the only thing that spells it out, and only
 * the detail endpoint returns it. Grouping therefore offers the two dimensions
 * the list *does* carry. Adding the id to the list response would make a real
 * tree possible and is the next thing worth doing on the API for this page.
 */
export function AssetsPage() {
  const t = useT();
  const [search, setSearch] = useState("");
  const [environment, setEnvironment] = useState("all");
  const [exposure, setExposure] = useState("all");
  const [type, setType] = useState("all");
  const [groupBy, setGroupBy] = useState<GroupKey>("none");
  const [page, setPage] = useState(0);

  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (environment !== "all") params.set("environment", environment);
  if (exposure !== "all") params.set("exposure", exposure);
  if (type !== "all") params.set("resource_type", type);
  params.set("limit", String(PAGE_SIZE));
  params.set("offset", String(page * PAGE_SIZE));

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["assets", search, environment, exposure, type, page],
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
        groupBy === "resource_type"
          ? resourceTypeLabel(asset.resource_type)
          : (asset.environment ?? "Unlabelled");
      map.set(key, [...(map.get(key) ?? []), asset]);
    }
    return [...map.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [sorted, groupBy]);

  const filtering =
    search !== "" || environment !== "all" || exposure !== "all" || type !== "all";
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
      />

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
          <Select value={type} onValueChange={resetTo(setType)}>
            <SelectTrigger size="sm" className="w-[150px]" aria-label="Filter by type">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All types</SelectItem>
              {types.map((value) => (
                <SelectItem key={value} value={value}>
                  {resourceTypeLabel(value)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={environment} onValueChange={resetTo(setEnvironment)}>
            <SelectTrigger size="sm" className="w-[160px]" aria-label="Filter by environment">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All environments</SelectItem>
              <SelectItem value="production">Production</SelectItem>
              <SelectItem value="development">Development</SelectItem>
            </SelectContent>
          </Select>

          <Select value={exposure} onValueChange={resetTo(setExposure)}>
            <SelectTrigger size="sm" className="w-[150px]" aria-label="Filter by exposure">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All exposure</SelectItem>
              <SelectItem value="CRITICAL">Critical</SelectItem>
              <SelectItem value="HIGH">High</SelectItem>
              <SelectItem value="MEDIUM">Medium</SelectItem>
              <SelectItem value="LOW">Low</SelectItem>
              <SelectItem value="UNKNOWN">Unknown</SelectItem>
            </SelectContent>
          </Select>

          <Select value={groupBy} onValueChange={(v) => setGroupBy((v as GroupKey) ?? "none")}>
            <SelectTrigger size="sm" className="w-[150px]" aria-label="Group assets">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="none">No grouping</SelectItem>
              <SelectItem value="resource_type">By type</SelectItem>
              <SelectItem value="environment">By environment</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {isLoading && <TableSkeleton columns={7} />}

      {error && (
        <ErrorState
          title="Could not load your assets"
          detail="CloudGuard could not reach its own API to read the inventory."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && assets.length === 0 && (
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
                  setPage(0);
                }}
              >
                Clear filters
              </Button>
            ) : (
              <Button variant="outline" render={<Link to="/scans" />}>
                Run a scan
              </Button>
            )
          }
        />
      )}

      {data && assets.length > 0 && (
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
