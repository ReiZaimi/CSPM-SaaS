import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ArrowLeftIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { CloudConnection, Provider } from "@/lib/types";
import { useT } from "@/i18n";
import { connectionStage, setupPath } from "@/lib/connectionStage";
import { SetupRail } from "@/components/connections/setup/SetupRail";
import { StepConsent } from "@/components/connections/setup/StepConsent";
import { StepDeploy } from "@/components/connections/setup/StepDeploy";
import { StepScope } from "@/components/connections/setup/StepScope";
import { StepSubscriptions } from "@/components/connections/setup/StepSubscriptions";
import { CardsSkeleton, PageHeader } from "@/components/common/states";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

/**
 * The connection wizard.
 *
 * Two routes, one component: `/connections/new` before anything exists, and
 * `/connections/:connectionId/setup` from the moment it does. The step shown is
 * derived from the connection rather than held in state, because setup leaves
 * this application twice -- to Microsoft for consent, to Azure Portal for the
 * role -- and returns through a full page load each time. The consent callback
 * redirects straight back to this URL, so coming back means arriving at the
 * next step rather than at a list with a card to find.
 *
 * The connection is re-read every five seconds until it can scan. That poll is
 * not only a status check: the backend re-probes both grants and runs discovery
 * inside the same request, so it is what actually advances the wizard while the
 * customer waits on somebody else.
 */
export function ConnectionSetupPage() {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { connectionId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  // Tracked separately from the query's own `isFetching`, which is true every
  // five seconds because of the poll -- a button reading "Checking…" on a timer
  // says the reader pressed something they did not.
  const [rechecking, setRechecking] = useState(false);

  const consentError = searchParams.get("consent_error");

  const detail = useQuery({
    queryKey: ["cloud-connection", connectionId],
    queryFn: () =>
      api
        .get<CloudConnection>(`/api/v1/cloud-connections/${connectionId}`)
        .then((r) => r.data),
    enabled: Boolean(connectionId),
    refetchInterval: (query) => (query.state.data?.is_ready_to_scan ? false : 5000),
    refetchIntervalInBackground: true,
  });

  const connection = detail.data ?? null;
  const stage = connectionStage(connection);
  // Which cloud the wizard is describing. Before a connection exists, the
  // picker in the first step decides; after it does, the connection itself is
  // the answer -- the provider is not editable, because the grant and the
  // artefact are both bound to it.
  const [chosen, setChosen] = useState<Provider>("azure");
  const provider = connection?.provider ?? chosen;

  const setCancelled = useMutation({
    mutationFn: (value: boolean) =>
      api.post(
        `/api/v1/cloud-connections/${connectionId}/${value ? "cancel" : "resume"}`,
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cloud-connection", connectionId] });
      queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
    },
    onError: (err) =>
      setError(err instanceof Error ? err.message : "Could not update the connection"),
  });

  // Discarding and starting again is how the scope gets changed: the scope is
  // what consent and the role assignment were both bound to, so there is no
  // edit that would leave either of them meaning what they meant.
  const discard = useMutation({
    mutationFn: () => api.del(`/api/v1/cloud-connections/${connectionId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
      navigate("/connections/new", { replace: true });
    },
    onError: (err) =>
      setError(err instanceof Error ? err.message : "Could not discard the connection"),
  });

  function dismissConsentError() {
    searchParams.delete("consent_error");
    setSearchParams(searchParams, { replace: true });
  }

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
      <div>
        <Link
          to="/connections"
          className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeftIcon className="size-3.5" />
          {t.setup.backToConnections}
        </Link>
        <PageHeader
          className="mt-3"
          title={connection ? connection.name : t.setup.title}
          description={t.setup.intro}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_20rem] lg:items-start">
        <Card>
          <CardContent className="pt-6">
            {connectionId && detail.isLoading && <CardsSkeleton count={1} />}

            {connectionId && detail.isError && (
              <Alert variant="destructive">
                <AlertTitle>This connection could not be loaded</AlertTitle>
                <AlertDescription>
                  <p>
                    It may have been removed. The connections list is the way back.
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-2"
                    onClick={() => navigate("/connections")}
                  >
                    {t.setup.backToConnections}
                  </Button>
                </AlertDescription>
              </Alert>
            )}

            {!connectionId && (
              <StepScope
                provider={provider}
                onProviderChange={setChosen}
                onCreated={(id) => navigate(setupPath(id), { replace: true })}
              />
            )}

            {connection && stage === "paused" && (
              <div className="flex flex-col gap-4">
                <div>
                  <h2 className="text-base font-semibold text-foreground">
                    {t.setup.paused}
                  </h2>
                  <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
                    {connection.status_detail ?? t.setup.pausedBody}
                  </p>
                </div>
                <div>
                  <Button
                    onClick={() => setCancelled.mutate(false)}
                    disabled={setCancelled.isPending}
                  >
                    {t.connection.resumeSetup}
                  </Button>
                </div>
              </div>
            )}

            {connection && stage === "consent" && (
              <StepConsent
                connection={connection}
                consentError={consentError}
                onDismissError={dismissConsentError}
              />
            )}

            {connection && stage === "deploy" && (
              <StepDeploy
                connection={connection}
                onRecheck={() => {
                  setRechecking(true);
                  void detail.refetch().finally(() => setRechecking(false));
                }}
                rechecking={rechecking}
                onDiscard={() => discard.mutate()}
                discarding={discard.isPending}
              />
            )}

            {connection && ["discover", "review", "done"].includes(stage) && (
              <StepSubscriptions connection={connection} onError={setError} />
            )}

            {error && (
              <Alert variant="destructive" className="mt-4">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {/* Leaving is a first-class way out of every waiting step. Both
                grants are somebody else's to give, and a wizard that can only
                be finished or abandoned makes a customer sit on a spinner for a
                colleague who is in a meeting. */}
            {connection && ["consent", "deploy", "discover"].includes(stage) && (
              <div className="mt-6 flex flex-wrap items-center gap-2 border-t border-border pt-4">
                <Button
                  variant="secondary"
                  onClick={() => navigate("/connections")}
                >
                  {t.setup.finishLater}
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => setCancelled.mutate(true)}
                  disabled={setCancelled.isPending}
                >
                  {t.connection.cancelSetupAction}
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        <SetupRail stage={stage} provider={provider} />
      </div>
    </div>
  );
}
