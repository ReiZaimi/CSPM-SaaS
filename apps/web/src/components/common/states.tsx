import { Fragment, type ComponentType, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { AlertCircleIcon } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { cn } from "@/lib/format";

/**
 * The page's own title block.
 *
 * Every page grew its own, and they drifted: three heading sizes, two spacing
 * rhythms, and a description that was sometimes above the actions and sometimes
 * beside them. One component means a reader's eye lands in the same place on
 * every screen.
 */
export function PageHeader({
  title,
  description,
  actions,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-start justify-between gap-4", className)}>
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight text-foreground">{title}</h1>
        {description && (
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{description}</p>
        )}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

/**
 * Where the reader is, and the way back up.
 *
 * Detail pages each had a lone "← Findings" button, which answers only one of
 * the two questions somebody arriving from a search result or a shared link
 * asks. A trail answers both: what this page is a detail *of*, and what it is
 * called -- and it is the same shape on every detail screen, so the way back is
 * always in the same place.
 *
 * The last entry is the page itself and is deliberately not a link: offering to
 * navigate to where you already are is noise.
 */
export function Breadcrumbs({
  trail,
  className,
}: {
  trail: { label: string; to?: string }[];
  className?: string;
}) {
  return (
    <Breadcrumb className={className}>
      <BreadcrumbList>
        {trail.map((crumb, index) => {
          const last = index === trail.length - 1;
          return (
            <Fragment key={`${crumb.label}-${index}`}>
              <BreadcrumbItem className="min-w-0">
                {crumb.to && !last ? (
                  <BreadcrumbLink render={<Link to={crumb.to} />}>
                    {crumb.label}
                  </BreadcrumbLink>
                ) : (
                  <BreadcrumbPage className="truncate">{crumb.label}</BreadcrumbPage>
                )}
              </BreadcrumbItem>
              {!last && <BreadcrumbSeparator />}
            </Fragment>
          );
        })}
      </BreadcrumbList>
    </Breadcrumb>
  );
}

/**
 * An empty state that says what to do next.
 *
 * "No data." tells the reader the query returned nothing, which they can see.
 * What they need is which of the several possible nothings this is -- nothing
 * found, nothing connected, nothing scanned yet -- because each sends them
 * somewhere different.
 */
export function EmptyState({
  title,
  detail,
  action,
  icon: Icon,
  className,
}: {
  title: string;
  detail?: ReactNode;
  action?: ReactNode;
  icon?: ComponentType<{ className?: string }>;
  className?: string;
}) {
  return (
    <Empty className={cn("border border-dashed", className)}>
      <EmptyHeader>
        {Icon && (
          <EmptyMedia variant="icon">
            <Icon className="size-5" />
          </EmptyMedia>
        )}
        <EmptyTitle>{title}</EmptyTitle>
        {detail && <EmptyDescription>{detail}</EmptyDescription>}
      </EmptyHeader>
      {action && <EmptyContent>{action}</EmptyContent>}
    </Empty>
  );
}

/**
 * An error a person can act on.
 *
 * Three parts, and the middle one is the part that was missing everywhere: what
 * this failure *costs*. "403 Forbidden" is a fact about a request; "identity
 * checks will report UNKNOWN until this is fixed" is a fact about the reader's
 * security posture, and only the second tells them whether to care now.
 */
export function ErrorState({
  title,
  detail,
  impact,
  action,
  onRetry,
  className,
}: {
  title: string;
  detail?: ReactNode;
  impact?: ReactNode;
  action?: ReactNode;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <Alert variant="destructive" className={className}>
      <AlertCircleIcon />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>
        {detail && <p>{detail}</p>}
        {impact && (
          <p className="text-muted-foreground">
            <span className="font-medium text-foreground">Impact: </span>
            {impact}
          </p>
        )}
        {(onRetry || action) && (
          <div className="mt-1 flex items-center gap-2">
            {onRetry && (
              <Button variant="outline" size="sm" onClick={onRetry}>
                Try again
              </Button>
            )}
            {action}
          </div>
        )}
      </AlertDescription>
    </Alert>
  );
}

/**
 * Loading placeholders shaped like the thing that is loading.
 *
 * A centred spinner tells the reader to wait and nothing else. A skeleton in
 * the shape of the page tells them what is coming, keeps the layout from
 * jumping when it arrives, and makes a slow request feel like progress rather
 * than a stall.
 */
export function TableSkeleton({ rows = 6, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <Card>
      <CardContent className="p-0">
        <div className="flex items-center gap-4 border-b px-4 py-3">
          {Array.from({ length: columns }).map((_, i) => (
            <Skeleton key={i} className={cn("h-3", i === 0 ? "w-48" : "w-20")} />
          ))}
        </div>
        {Array.from({ length: rows }).map((_, row) => (
          <div key={row} className="flex items-center gap-4 border-b px-4 py-4 last:border-0">
            {Array.from({ length: columns }).map((_, i) => (
              <Skeleton key={i} className={cn("h-4", i === 0 ? "w-64" : "w-16")} />
            ))}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

export function CardsSkeleton({ count = 3 }: { count?: number }) {
  return (
    <div className="flex flex-col gap-3">
      {Array.from({ length: count }).map((_, i) => (
        <Card key={i}>
          <CardHeader>
            <Skeleton className="h-4 w-56" />
            <Skeleton className="h-3 w-80" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-16 w-full" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

/**
 * The dashboard's own shape, held while it loads.
 *
 * Shaped like the page rather than generically, because that is the whole
 * point: the layout does not jump when the data lands, and a slow request reads
 * as progress rather than as a stall. It follows the same order the page argues
 * in — score and trend, severity, coverage, risks beside the route, then
 * remediation beside changes.
 */
export function DashboardSkeleton() {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start justify-between gap-4">
        <div className="flex flex-col gap-2">
          <Skeleton className="h-6 w-32" />
          <Skeleton className="h-4 w-80 max-w-full" />
        </div>
        <Skeleton className="h-7 w-40" />
      </div>

      <div className="grid gap-px overflow-hidden rounded-xl bg-border ring-1 ring-foreground/10 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
        <div className="flex flex-col gap-4 bg-card p-5">
          <Skeleton className="h-3 w-24" />
          <Skeleton className="h-14 w-32" />
          <Skeleton className="h-1.5 w-full" />
          <Skeleton className="h-3 w-48" />
        </div>
        <div className="flex flex-col gap-3 bg-card p-5">
          <Skeleton className="h-3 w-24" />
          <Skeleton className="h-40 w-full" />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-xl bg-border ring-1 ring-foreground/10 sm:grid-cols-3 lg:grid-cols-5">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="flex flex-col gap-2 bg-card px-4 py-3.5">
            <Skeleton className="h-4 w-16" />
            <Skeleton className="h-8 w-10" />
          </div>
        ))}
      </div>

      <div className="flex flex-col gap-3 rounded-xl bg-card p-5 ring-1 ring-foreground/10">
        <Skeleton className="h-4 w-44" />
        <Skeleton className="h-3 w-full max-w-xl" />
        <Skeleton className="h-1 w-full" />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {Array.from({ length: 2 }).map((_, i) => (
          <div
            key={i}
            className="flex flex-col gap-3 rounded-xl bg-card p-5 ring-1 ring-foreground/10"
          >
            <Skeleton className="h-4 w-36" />
            <Skeleton className="h-3 w-full max-w-sm" />
            <Skeleton className="h-24 w-full" />
          </div>
        ))}
      </div>
    </div>
  );
}

export function DetailSkeleton() {
  return (
    <div className="flex flex-col gap-5">
      <Skeleton className="h-3 w-32" />
      <Skeleton className="h-8 w-2/3" />
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="flex flex-col gap-4 lg:col-span-2">
          <CardsSkeleton count={3} />
        </div>
        <CardsSkeleton count={2} />
      </div>
    </div>
  );
}
