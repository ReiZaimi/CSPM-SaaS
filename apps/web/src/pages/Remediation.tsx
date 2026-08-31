import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "@/lib/api";
import type { RemediationTask } from "@/lib/types";
import { useT } from "@/i18n";
import { Badge, Button, Card, EmptyState, StatusPill } from "@/components/ui";
import { formatDate, formatEffort } from "@/lib/format";
import { ErrorState, TableSkeleton } from "@/components/common/states";

export function RemediationPage() {
  const t = useT();
  const queryClient = useQueryClient();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["remediation"],
    queryFn: () => api.get<RemediationTask[]>("/api/v1/remediation").then((r) => r.data),
  });

  const update = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.patch(`/api/v1/remediation/${id}`, { status }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["remediation"] }),
  });

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{t.remediation.title}</h1>
        <p className="mt-1 text-sm text-stone-500">
          Ordered by impact against effort. Marking work done does not close a finding — a scan
          does.
        </p>
      </div>

      {isLoading && <TableSkeleton />}
      {error && <ErrorState
          title="Could not load this page"
          detail="CloudGuard could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />}
      {data && data.length === 0 && (
        <EmptyState
          title={t.remediation.empty}
          detail="Assign a finding from its detail page to start tracking the work."
        />
      )}

      <div className="space-y-3">
        {data?.map((task) => (
          <Card key={task.id}>
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <Badge level={task.priority} />
                <StatusPill status={task.status} />
                <Link
                  to={`/findings/${task.finding_id}`}
                  className="text-sm text-stone-800 hover:underline"
                >
                  View finding
                </Link>
              </div>
              <div className="flex flex-wrap items-center gap-4 text-xs text-stone-500">
                <span>{formatEffort(task.estimated_effort_minutes)}</span>
                {task.due_date && <span>Due {formatDate(task.due_date)}</span>}
                {task.status !== "DONE" && (
                  <Button
                    variant="secondary"
                    onClick={() => update.mutate({ id: task.id, status: "DONE" })}
                  >
                    Mark done
                  </Button>
                )}
              </div>
            </div>
            {task.notes && <p className="mt-3 text-sm text-stone-600">{task.notes}</p>}
          </Card>
        ))}
      </div>
    </div>
  );
}
