import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { RadarIcon } from "lucide-react";

import { api } from "@/lib/api";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { resourceTypeLabel } from "@/lib/format";

interface Reached {
  id: string;
  name: string;
  resource_type: string;
  data_sensitivity: string;
}

/**
 * What this asset can act on, if it were taken.
 *
 * Loaded on demand rather than with the page, and that is a cost decision
 * rather than a stylistic one: the endpoint rebuilds the organization's whole
 * asset graph to answer, so firing it automatically would put that behind every
 * asset anybody merely clicked into.
 *
 * Keyed on the provider resource id, not the row id -- the graph's vertices are
 * the cloud's own identifiers, and the database UUID names nothing in it.
 */
export function BlastRadius({
  providerResourceId,
  name,
}: {
  providerResourceId: string;
  name: string;
}) {
  const [asked, setAsked] = useState(false);

  const { data, isLoading, error } = useQuery({
    queryKey: ["blast-radius", providerResourceId],
    queryFn: () =>
      api
        .get<Reached[]>(
          `/api/v1/attack-paths/blast-radius/${encodeURIComponent(providerResourceId)}`,
        )
        .then((r) => r.data),
    enabled: asked,
    retry: false,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Blast radius</CardTitle>
        <CardDescription>
          What {name} could act on if an attacker controlled it
        </CardDescription>
      </CardHeader>
      <CardContent>
        {!asked && (
          <Button variant="outline" size="sm" onClick={() => setAsked(true)}>
            <RadarIcon data-icon="inline-start" />
            Work out reach
          </Button>
        )}

        {asked && isLoading && (
          <div className="flex flex-col gap-2">
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-4 w-64" />
          </div>
        )}

        {asked && error && (
          <p className="text-sm text-muted-foreground">
            This asset is not a vertex in the current graph — it may not have been in the
            most recent scan.
          </p>
        )}

        {data && data.length === 0 && (
          <p className="text-sm text-muted-foreground">
            Nothing. This asset holds no role and runs as no identity that reaches
            anything else CloudGuard has seen.
          </p>
        )}

        {data && data.length > 0 && (
          <ul className="flex flex-col divide-y">
            {data.map((reached) => (
              <li
                key={reached.id}
                className="flex items-center gap-3 py-2 text-sm first:pt-0 last:pb-0"
              >
                <span className="min-w-0 flex-1 truncate">{reached.name}</span>
                <span className="shrink-0 text-xs text-muted-foreground">
                  {resourceTypeLabel(reached.resource_type)}
                </span>
                <SeverityBadge level={reached.data_sensitivity} size="sm" />
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
