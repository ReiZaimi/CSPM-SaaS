import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { CloudIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { CloudConnection } from "@/lib/types";
import { useT } from "@/i18n";
import { ConnectionForm } from "@/components/ConnectWizard";
import { ConnectionCard } from "@/components/connections/ConnectionCard";
import { CardsSkeleton, EmptyState, PageHeader } from "@/components/common/states";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

/**
 * The connections page.
 *
 * Lists existing connections with live status, and offers a form to create new
 * ones. After consent, the callback redirects here with `?id=<connection_id>`,
 * which auto-expands the matching card.
 *
 * A connection's own card is `components/connections/ConnectionCard.tsx`. It is
 * the largest single thing in the product -- a consent step, a deployment step,
 * subscription scoping, scheduling and removal, each with its own failure
 * state -- and keeping it, the schedule control and the removal confirmation in
 * one file with this list made the whole setup flow one 750-line read.
 */
export function ConnectPage() {
  const t = useT();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [showForm, setShowForm] = useState(false);

  const consentError = searchParams.get("consent_error");
  const expandedId = searchParams.get("id");

  const connections = useQuery({
    queryKey: ["cloud-connections"],
    queryFn: () => api.get<CloudConnection[]>("/api/v1/cloud-connections").then((r) => r.data),
  });

  function handleCreated(id: string) {
    setShowForm(false);
    setSearchParams({ id });
    queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
  }

  function dismissError() {
    searchParams.delete("consent_error");
    setSearchParams(searchParams);
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeader title={t.connection.title} description={t.connection.intro} />
        {!showForm && (
          <Button className="shrink-0" onClick={() => setShowForm(true)}>
            {t.connection.connectAzure}
          </Button>
        )}
      </div>

      {/* Azure's own reason, carried through the callback. Dismissible rather
          than sticky: it describes one attempt, and the next one starts from
          the button above. */}
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

      {showForm && (
        <ConnectionForm onCreated={handleCreated} onClose={() => setShowForm(false)} />
      )}

      {connections.isLoading && <CardsSkeleton count={2} />}

      {connections.data?.length === 0 && !showForm && (
        <EmptyState
          icon={CloudIcon}
          title={t.connection.noConnections}
          detail={t.connection.noConnectionsHelp}
          action={
            <Button onClick={() => setShowForm(true)}>{t.connection.connectAzure}</Button>
          }
        />
      )}

      {connections.data?.map((connection) => (
        <ConnectionCard
          key={connection.id}
          connection={connection}
          defaultExpanded={connection.id === expandedId}
        />
      ))}
    </div>
  );
}
