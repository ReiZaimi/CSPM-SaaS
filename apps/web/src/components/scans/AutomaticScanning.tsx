import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api } from "@/lib/api";
import type { CloudConnection } from "@/lib/types";
import { ScheduleControl } from "@/components/scans/ScheduleControl";
import { buttonVariants } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/format";

/**
 * How often CloudGuard reads each environment without being asked.
 *
 * It lives here rather than on the connection card, where it started, because
 * of what a reader is doing on each page. The connections page answers "can
 * CloudGuard see my cloud" — a setup question, asked once. This page answers
 * "when was my cloud last read, and when will it be read next", and a schedule
 * is the second half of that sentence: a scan history with no visible cadence
 * makes the gaps between runs look like something that happened rather than
 * something that was chosen.
 *
 * One control per connection, because the interval is a property of the grant
 * rather than of a subscription — every subscription beneath a connection is
 * read on the same clock.
 */
export function AutomaticScanning({
  onError,
}: {
  onError: (message: string) => void;
}) {
  const { data, isLoading } = useQuery({
    queryKey: ["cloud-connections"],
    queryFn: () =>
      api.get<CloudConnection[]>("/api/v1/cloud-connections").then((r) => r.data),
    retry: false,
  });

  const connections = Array.isArray(data)
    ? data.filter((connection) => connection.is_verified)
    : [];

  if (isLoading) return <Skeleton className="h-32 w-full rounded-xl" />;

  return (
    <section
      aria-labelledby="automatic-scanning"
      className="overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <header className="flex flex-wrap items-start justify-between gap-3 px-5 py-4">
        <div>
          <h2 id="automatic-scanning" className="text-sm font-semibold">
            Automatic scanning
          </h2>
          <p className="mt-0.5 max-w-2xl text-xs leading-relaxed text-muted-foreground">
            A posture ages the moment it is measured — cloud environments change
            daily, and a scan from last month describes an environment that has
            moved on. This is how often CloudGuard re-reads each one without
            being asked.
          </p>
        </div>
      </header>

      <div className="border-t px-5 py-4">
        {connections.length === 0 ? (
          <div className="flex flex-wrap items-center gap-3">
            <p className="text-sm text-muted-foreground">
              No verified connection to put on a schedule yet.
            </p>
            <Link
              to="/connections"
              className={cn(buttonVariants({ variant: "outline", size: "sm" }))}
            >
              Connect Azure
            </Link>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {connections.map((connection) => (
              <div key={connection.id}>
                {connections.length > 1 && (
                  <p className="mb-1 text-xs font-medium text-muted-foreground">
                    {connection.name}
                  </p>
                )}
                <ScheduleControl connection={connection} onError={onError} />
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
