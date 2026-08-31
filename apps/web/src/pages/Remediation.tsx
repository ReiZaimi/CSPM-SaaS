import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { WrenchIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { RemediationTask } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { formatDate, formatEffort } from "@/lib/format";

/**
 * The work queue.
 *
 * "Mark done" records that somebody did the work; it does not resolve the
 * finding, and the page says so where the button is rather than only in the
 * introduction. Only a scan observing the fixed state closes a finding
 * (RULE_ENGINE.md section 3), and a queue that let a person tick a security
 * problem closed would be the one place in this product where saying so made
 * it true.
 */
export function RemediationPage() {
  const t = useT();
  const queryClient = useQueryClient();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["remediation"],
    queryFn: () =>
      api.get<RemediationTask[]>("/api/v1/remediation").then((r) => r.data),
  });

  const update = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.patch(`/api/v1/remediation/${id}`, { status }),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["remediation"] }),
  });

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t.remediation.title}
        description="Ordered by impact against effort. Marking work done does not close a finding — a scan does."
      />

      {isLoading && <CardsSkeleton />}

      {error && (
        <ErrorState
          title="Could not load the remediation queue"
          detail="CloudGuard could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && data.length === 0 && (
        <EmptyState
          icon={WrenchIcon}
          title={t.remediation.empty}
          detail="Assign a finding from its detail page to start tracking the work."
          action={
            <Button variant="outline" render={<Link to="/findings" />}>
              Go to findings
            </Button>
          }
        />
      )}

      <div className="flex flex-col gap-3">
        {data?.map((task) => {
          const marking = update.isPending && update.variables?.id === task.id;
          return (
            <Card key={task.id}>
              <CardContent className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <SeverityBadge level={task.priority} />
                  <StatusPill status={task.status} />
                  <Link
                    to={`/findings/${task.finding_id}`}
                    className="text-sm text-foreground hover:underline"
                  >
                    View finding
                  </Link>
                </div>
                <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
                  <span>{formatEffort(task.estimated_effort_minutes)}</span>
                  {task.due_date && (
                    <span>Due {formatDate(task.due_date)}</span>
                  )}
                  {task.status !== "DONE" && (
                    <Button
                      variant="secondary"
                      size="sm"
                      disabled={marking}
                      onClick={() =>
                        update.mutate({ id: task.id, status: "DONE" })
                      }
                    >
                      {marking && <Spinner data-icon="inline-start" />}
                      Mark done
                    </Button>
                  )}
                </div>
              </CardContent>
              {task.notes && (
                <CardFooter className="border-t pt-4 text-sm text-muted-foreground">
                  {task.notes}
                </CardFooter>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}
