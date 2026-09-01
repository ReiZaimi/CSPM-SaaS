import {
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { WrenchIcon } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { FindingDetail, RemediationTask } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Button, buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { formatDate, formatEffort, resourceTypeLabel } from "@/lib/format";

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

  /**
   * What each task is actually about.
   *
   * `GET /remediation` returns the task and nothing of the finding behind it --
   * no title, no asset, no rule -- so this queue could say only "View finding",
   * and a reader deciding what to work on next had to open every card to learn
   * what the work was. That is an API limitation rather than a UI one, and it
   * is worked around here rather than by widening the endpoint: the finding is
   * read per task under the same cache key its own page uses, so opening one
   * from this list costs no request at all.
   */
  const findings = useQueries({
    queries: (data ?? []).map((task) => ({
      queryKey: ["finding", task.finding_id],
      queryFn: () =>
        api
          .get<FindingDetail>(`/api/v1/findings/${task.finding_id}`)
          .then((r) => r.data),
      staleTime: 60_000,
      retry: false,
    })),
  });

  const update = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.patch<RemediationTask & { note?: string }>(
        `/api/v1/remediation/${id}`,
        { status },
      ),
    // The API answers a completed task with what happens next -- CloudGuard
    // will look again, and only an observation closes the finding. That
    // sentence used to be discarded, so marking work done gave no feedback at
    // all and quietly implied the finding was now closed.
    onSuccess: ({ data: task }) => {
      queryClient.invalidateQueries({ queryKey: ["remediation"] });
      queryClient.invalidateQueries({ queryKey: ["finding", task.finding_id] });
      toast.success("Marked done", {
        description:
          task.note ??
          "CloudGuard will check the environment and close the finding once the change appears.",
      });
    },
    onError: (err) =>
      toast.error("Could not update this task", {
        description:
          err instanceof Error ? err.message : "The API rejected the change.",
      }),
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
            <Link
              to="/findings"
              className={buttonVariants({ variant: "outline" })}
            >
              Go to findings
            </Link>
          }
        />
      )}

      <div className="flex flex-col gap-3">
        {data?.map((task) => (
          <TaskCard
            key={task.id}
            task={task}
            finding={findings.find((q) => q.data?.id === task.finding_id)?.data}
            marking={update.isPending && update.variables?.id === task.id}
            onDone={() => update.mutate({ id: task.id, status: "DONE" })}
          />
        ))}
      </div>
    </div>
  );
}

/**
 * One job, said as a job.
 *
 * The card this replaces led with two badges and a link reading "View finding",
 * which named the queue's own vocabulary and none of the reader's. What decides
 * whether a task is worked next is what is wrong, on what, and how long it
 * takes -- so the title of the finding is the card, and the badges qualify it.
 */
function TaskCard({
  task,
  finding,
  marking,
  onDone,
}: {
  task: RemediationTask;
  finding: FindingDetail | undefined;
  marking: boolean;
  onDone: () => void;
}) {
  return (
    <Card>
      <CardContent className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge level={task.priority} />
            <StatusPill status={task.status} />
          </div>

          {finding ? (
            <Link
              to={`/findings/${task.finding_id}`}
              className="mt-2 block text-sm font-medium text-foreground hover:underline"
            >
              {finding.title}
            </Link>
          ) : (
            // The row keeps its height while the finding arrives, so a queue
            // does not reflow under the reader's cursor.
            <Skeleton className="mt-2.5 h-4 w-72 max-w-full" />
          )}

          <p className="mt-1 truncate text-xs text-muted-foreground">
            {finding?.resource
              ? `${finding.resource.name} · ${resourceTypeLabel(finding.resource.resource_type)}`
              : finding
                ? "Tenant-wide — no single asset carries this"
                : " "}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
          <span>{formatEffort(task.estimated_effort_minutes)}</span>
          {task.due_date && <span>Due {formatDate(task.due_date)}</span>}
          {task.status !== "DONE" && (
            <Button
              variant="secondary"
              size="sm"
              disabled={marking}
              onClick={onDone}
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
}
