import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { WrenchIcon } from "lucide-react";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type { FindingStatus, RemediationTask } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { formatDate, formatEffort } from "@/lib/format";

/**
 * The door into the remediation queue.
 *
 * `POST /remediation` has always existed and nothing in the UI called it: the
 * queue's own empty state told the reader to "assign a finding from its detail
 * page", and the detail page had no way to. So the queue could only ever be
 * empty, and the one screen that ranks work by impact against effort was
 * unreachable from the screens that produce the work.
 *
 * It sits under the recommended fix rather than beside "Rescan to verify",
 * because tracking work is a statement about who is going to do what is written
 * above it -- and because the verify row must not blur into a row where one
 * button records intent and another asks for proof. Assigning does move the
 * finding to IN_PROGRESS server-side; it does not close it, and the caption
 * says so where the button is.
 */
export function TrackFix({
  findingId,
  status,
  effortMinutes,
}: {
  findingId: string;
  status: FindingStatus;
  effortMinutes?: number;
}) {
  const queryClient = useQueryClient();

  // The whole queue, under the key the queue page itself uses: the finding
  // detail response carries no task, and widening it for one button would put
  // a join on the hot path of the page the product is really about.
  const tasks = useQuery({
    queryKey: ["remediation"],
    queryFn: () =>
      api.get<RemediationTask[]>("/api/v1/remediation").then((r) => r.data),
    staleTime: 30_000,
    retry: false,
  });

  const rows = Array.isArray(tasks.data) ? tasks.data : [];
  // A cancelled task is not tracking: the work was called off, and the finding
  // can be picked up again.
  const task = rows.find(
    (row) => row.finding_id === findingId && row.status !== "CANCELLED",
  );

  const track = useMutation({
    mutationFn: () =>
      api.post<RemediationTask>("/api/v1/remediation", {
        finding_id: findingId,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["remediation"] });
      queryClient.invalidateQueries({ queryKey: ["finding", findingId] });
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      toast.success("Added to the remediation queue", {
        description:
          "Prioritised by impact against effort. The finding stays open until a scan observes the fix.",
      });
    },
    onError: (err) =>
      toast.error("Could not track this fix", {
        description:
          err instanceof ApiError ? err.message : "The API rejected the request.",
      }),
  });

  if (tasks.isLoading) return <Skeleton className="h-9 w-48" />;

  if (task) {
    return (
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
        <WrenchIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
        <span className="text-foreground">
          {task.status === "DONE"
            ? `Marked done ${formatDate(task.completed_at)}`
            : `In the remediation queue since ${formatDate(task.created_at)}`}
        </span>
        <Link
          to="/remediation"
          className="text-sm underline underline-offset-2 text-muted-foreground hover:text-foreground"
        >
          Open the queue
        </Link>
      </div>
    );
  }

  // Nothing to schedule. A verified fix has no work left in it, and an accepted
  // risk is a decision not to do the work -- offering to queue either would ask
  // the reader to undo a conclusion the product has already recorded.
  if (status === "RESOLVED" || status === "ACCEPTED_RISK") return null;

  return (
    <div className="flex flex-wrap items-center gap-3">
      <Button
        variant="secondary"
        disabled={track.isPending}
        onClick={() => track.mutate()}
      >
        {track.isPending ? (
          <Spinner data-icon="inline-start" />
        ) : (
          <WrenchIcon data-icon="inline-start" />
        )}
        Track this fix
      </Button>
      <p className="text-xs text-muted-foreground">
        Puts it in the remediation queue
        {effortMinutes ? ` as ${formatEffort(effortMinutes)} of work` : ""}, ranked
        against everything else open. It does not close the finding — a scan does.
      </p>
    </div>
  );
}
