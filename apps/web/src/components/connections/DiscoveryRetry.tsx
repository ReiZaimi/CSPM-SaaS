import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { CloudConnection } from "@/lib/types";
import { useT } from "@/i18n";
import { Button } from "@/components/ui/button";

/**
 * Verified, with nothing beneath it.
 *
 * Both grants work and CloudGuard still cannot see a subscription. Two very
 * different causes look identical from here -- a role assignment that has not
 * propagated yet, and one deployed at a scope this connection does not cover --
 * and only one of them is fixed by asking again, so the copy names both rather
 * than implying the button is the answer.
 */
export function DiscoveryRetry({
  connection,
  onError,
  compact = false,
}: {
  connection: CloudConnection;
  onError?: (message: string) => void;
  /** Just the button, for a list that has already found something. */
  compact?: boolean;
}) {
  const t = useT();
  const queryClient = useQueryClient();

  const rediscover = useMutation({
    mutationFn: () => api.post(`/api/v1/cloud-connections/${connection.id}/discover`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cloud-connection", connection.id] });
      queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
    },
    onError: (err) =>
      onError?.(err instanceof Error ? err.message : "Could not look for subscriptions"),
  });

  const button = (
    <Button
      className={compact ? undefined : "mt-3"}
      variant="secondary"
      size={compact ? "sm" : "default"}
      disabled={rediscover.isPending}
      onClick={() => rediscover.mutate()}
    >
      {rediscover.isPending ? t.connection.lookingAgain : t.connection.lookAgain}
    </Button>
  );

  if (compact) return button;

  return (
    <div>
      <p className="text-sm font-medium text-foreground">
        {t.connection.noSubscriptionsTitle}
      </p>
      <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
        {t.connection.noSubscriptionsBody}
      </p>
      {button}
    </div>
  );
}
