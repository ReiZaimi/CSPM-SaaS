import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";

import { api } from "@/lib/api";
import type { CloudConnection } from "@/lib/types";
import { useT } from "@/i18n";
import { ConnectEmpty } from "@/components/connections/ConnectEmpty";
import { ConnectionRow } from "@/components/connections/ConnectionRow";
import { CardsSkeleton, PageHeader } from "@/components/common/states";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/format";

/**
 * The connections page: one row per connection, opened for the detail.
 *
 * It answers a question about the estate rather than about any one connection
 * -- is every environment being read, and how recently -- so the shape is a
 * table of rows that can be compared at a glance, not a column of cards each
 * describing itself at length. A row's own detail, its subscriptions, cadence
 * and access, is one click away in `ConnectionRow`.
 *
 * Setup lives in the wizard at `/connections/new` and `/connections/:id/setup`.
 * This page holds no setup steps of its own, so there is one flow rather than
 * two that drifted.
 */
export function ConnectPage() {
  const t = useT();
  const [searchParams, setSearchParams] = useSearchParams();

  // Only reached when the consent callback could not tell which connection the
  // failure belonged to -- a tampered or expired state. With an id it redirects
  // into the wizard instead, where the retry sits next to the explanation.
  const consentError = searchParams.get("consent_error");
  const expandedId = searchParams.get("id");

  const connections = useQuery({
    queryKey: ["cloud-connections"],
    queryFn: () => api.get<CloudConnection[]>("/api/v1/cloud-connections").then((r) => r.data),
  });

  function dismissError() {
    searchParams.delete("consent_error");
    setSearchParams(searchParams);
  }

  const rows = connections.data ?? [];

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title={t.connection.title}
        description={t.connection.intro}
        actions={
          rows.length > 0 ? (
            <Link to="/connections/new" className={cn(buttonVariants())}>
              {t.connection.connectCloud}
            </Link>
          ) : undefined
        }
      />

      {consentError && (
        <Alert variant="destructive">
          <AlertTitle>Consent failed</AlertTitle>
          <AlertDescription>
            <p>{consentError}</p>
            <Button variant="outline" size="sm" className="mt-2" onClick={dismissError}>
              Dismiss
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {connections.isLoading && <CardsSkeleton count={2} />}

      {connections.isSuccess && rows.length === 0 && <ConnectEmpty />}

      {rows.length > 0 && (
        <div className="overflow-hidden rounded-xl border border-border bg-card">
          {/* Column labels, not a `<table>`: every row opens into a two-column
              panel, which a table cell cannot hold without either colspan
              gymnastics or a second nested grid. The labels are hidden on
              narrow screens, where each row stacks and carries its own. */}
          <div
            aria-hidden
            className="hidden px-5 py-2.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground md:grid md:grid-cols-[minmax(0,2.2fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.1fr)_auto] md:gap-4"
          >
            <span>{t.connection.columnConnection}</span>
            <span>{t.connection.columnStatus}</span>
            <span>{t.connection.columnSubscriptions}</span>
            <span>{t.connection.columnLastRead}</span>
            <span className="text-right">{t.connection.columnActions}</span>
          </div>

          {rows.map((connection) => (
            <ConnectionRow
              key={connection.id}
              connection={connection}
              defaultExpanded={connection.id === expandedId}
            />
          ))}
        </div>
      )}
    </div>
  );
}
