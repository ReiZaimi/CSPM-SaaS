import { lazy, Suspense, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChevronRightIcon, FolderIcon, LayersIcon, UsersIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Asset, AssetScopeNode } from "@/lib/types";
import { CardsSkeleton, EmptyState, ErrorState } from "@/components/common/states";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, resourceTypeLabel } from "@/lib/format";

/** How many assets a group shows inline before it defers to the list. */
const INLINE_LIMIT = 25;

/** Recharts, loaded only once there is an estate to draw. */
const EstateTreemap = lazy(() =>
  import("@/components/charts/EstateTreemap").then((m) => ({
    default: m.EstateTreemap,
  })),
);

/**
 * The estate as it is actually organised, rather than as one long list.
 *
 * The flat inventory answers "what do I have". It cannot answer "which part of
 * my estate is the problem", and that is the question with an owner attached: a
 * resource group usually has one and a subscription almost always does, so the
 * tree is also the shortest route from a number to a person.
 *
 * Counted server-side over the whole estate, deliberately. The list pages at
 * fifty, and a tree built from one page of it would show a resource group twice
 * — once on each page its assets straddled — with a fraction of its findings
 * each time. Every level is ordered worst-first for the same reason the list
 * is: an inventory in a security product is a queue, not a directory.
 */
export function AssetTree() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["asset-hierarchy"],
    queryFn: () =>
      api.get<AssetScopeNode[]>("/api/v1/assets/hierarchy").then((r) => r.data),
  });

  if (isLoading) return <CardsSkeleton count={2} />;

  if (error) {
    return (
      <ErrorState
        title="Could not lay out your estate"
        detail="CloudGuard could not reach its own API to read the inventory."
        impact="Nothing about your environment has changed — this is a problem displaying it."
        onRetry={() => refetch()}
      />
    );
  }

  if (!data || data.length === 0) {
    return (
      <EmptyState
        icon={LayersIcon}
        title="Nothing discovered yet"
        detail="Once a scan completes, the subscriptions it read and the resource groups inside them appear here."
      />
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Where the problem is concentrated, before the reader starts opening
          things. Area is the right encoding exactly once in this product: a
          tree names the parts and a table ranks them, and neither answers
          "one team or six". */}
      <Suspense fallback={<Skeleton className="h-48 w-full rounded-xl" />}>
        <EstateTreemap
          scopes={data}
          className="h-48 w-full overflow-hidden rounded-xl ring-1 ring-foreground/10"
        />
      </Suspense>

      <Card className="overflow-hidden py-0">
        <CardContent className="px-0">
          <ul>
            {data.map((scope) => (
              <ScopeRow key={scope.id} scope={scope} />
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}

function ScopeRow({ scope }: { scope: AssetScopeNode }) {
  // The worst scope opens by itself: a tree that starts fully closed makes the
  // reader click to discover what the page was already able to tell them.
  const [open, setOpen] = useState(scope.open_findings > 0);
  const Icon = scope.kind === "DIRECTORY" ? UsersIcon : LayersIcon;

  return (
    <li className="border-b last:border-0">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex w-full items-center gap-2.5 px-4 py-2.5 text-left transition-colors hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
      >
        <ChevronRightIcon
          className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")}
          aria-hidden
        />
        <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
        <span className="min-w-0 flex-1 truncate text-sm font-medium">{scope.name}</span>
        <Counts assets={scope.asset_count} findings={scope.open_findings} />
      </button>

      {open && (
        <ul className="border-t bg-muted/20">
          {scope.groups.map((group) => (
            <GroupRow
              key={group.name ?? "__subscription__"}
              scopeId={scope.id}
              group={group}
            />
          ))}
        </ul>
      )}
    </li>
  );
}

function GroupRow({
  scopeId,
  group,
}: {
  scopeId: string;
  group: AssetScopeNode["groups"][number];
}) {
  const [open, setOpen] = useState(false);

  const params = new URLSearchParams();
  params.set("subscription_id", scopeId);
  if (group.name) params.set("resource_group", group.name);
  params.set("limit", String(INLINE_LIMIT));

  const assets = useQuery({
    queryKey: ["asset-hierarchy-group", scopeId, group.name],
    queryFn: () =>
      api.get<Asset[]>(`/api/v1/assets?${params.toString()}`).then((r) => ({
        rows: r.data,
        total: (r.meta as { total?: number } | undefined)?.total ?? r.data.length,
      })),
    // Only when somebody opens it. An estate with forty resource groups would
    // otherwise fire forty requests to draw a closed tree.
    enabled: open,
  });

  return (
    <li className="border-b last:border-0">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex w-full items-center gap-2.5 py-2 pl-10 pr-4 text-left transition-colors hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
      >
        <ChevronRightIcon
          className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")}
          aria-hidden
        />
        <FolderIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
        <span className="min-w-0 flex-1 truncate text-sm">
          {/* Assets that sit directly in the subscription rather than in any
              group. Named as that rather than as "Ungrouped", which would read
              as a tagging oversight instead of as where they actually are. */}
          {group.name ?? (
            <span className="text-muted-foreground">Directly in the subscription</span>
          )}
        </span>
        <Counts assets={group.asset_count} findings={group.open_findings} />
      </button>

      {open && (
        <div className="border-t bg-background pb-2 pl-16 pr-4 pt-2">
          {assets.isLoading && <Skeleton className="h-4 w-56" />}

          {assets.data && (
            <ul className="flex flex-col">
              {assets.data.rows.map((asset) => (
                <li key={asset.id} className="flex items-center gap-3 py-1.5">
                  <Link
                    to={`/assets/${asset.id}`}
                    className="min-w-0 flex-1 truncate text-sm hover:underline"
                  >
                    {asset.name}
                  </Link>
                  <span className="hidden shrink-0 text-xs text-muted-foreground sm:block">
                    {resourceTypeLabel(asset.resource_type)}
                  </span>
                  <SeverityBadge level={asset.public_exposure} size="sm" />
                  <span
                    className={cn(
                      "w-8 shrink-0 text-right text-xs tabular-nums",
                      asset.open_findings === 0
                        ? "text-muted-foreground"
                        : "font-medium text-foreground",
                    )}
                  >
                    {asset.open_findings}
                  </span>
                </li>
              ))}

              {assets.data.total > assets.data.rows.length && (
                <li className="pt-1.5">
                  {/* Said rather than truncated silently: a group showing 25 of
                      60 with nothing on screen saying so is the same bug the
                      list had before it started reporting its true total. */}
                  <span className="text-xs text-muted-foreground">
                    Showing {assets.data.rows.length} of {assets.data.total}.{" "}
                  </span>
                  <Link
                    to={`/assets?subscription_id=${encodeURIComponent(scopeId)}${
                      group.name
                        ? `&resource_group=${encodeURIComponent(group.name)}`
                        : ""
                    }`}
                    className="text-xs underline underline-offset-2"
                  >
                    Open this group in the list
                  </Link>
                </li>
              )}
            </ul>
          )}
        </div>
      )}
    </li>
  );
}

/** Assets and what is wrong in them, in that order and always both. */
function Counts({ assets, findings }: { assets: number; findings: number }) {
  return (
    <span className="flex shrink-0 items-center gap-4 text-xs tabular-nums">
      <span className="text-muted-foreground">
        {assets} asset{assets === 1 ? "" : "s"}
      </span>
      <span
        className={cn(
          "w-24 text-right",
          findings === 0 ? "text-muted-foreground" : "font-medium text-critical",
        )}
      >
        {findings} open finding{findings === 1 ? "" : "s"}
      </span>
    </span>
  );
}
