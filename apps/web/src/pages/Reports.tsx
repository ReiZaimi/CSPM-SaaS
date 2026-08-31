import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { DownloadIcon, ExternalLinkIcon, FileTextIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { useT } from "@/i18n";
import { ErrorState, PageHeader } from "@/components/common/states";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";

type Kind = "executive" | "technical";

/**
 * The evidence, fixed to a moment and made portable.
 *
 * Everything else in the product answers a question as it is asked. A report
 * is the same evidence written down so it can be filed, sent to a board, or
 * handed to an auditor -- and that difference is why the reports carry their
 * caveats printed on the cover rather than behind a tooltip: nobody can ask a
 * PDF a follow-up question.
 *
 * Nothing is listed here because nothing is stored. A library of past reports
 * would be a set of claims that outlive the evidence behind them, with no
 * honest way to say which is current.
 */
export function ReportsPage() {
  const t = useT();
  const [failure, setFailure] = useState<{ title: string; detail: string } | null>(null);

  const download = useMutation({
    mutationFn: async (kind: Kind) => {
      const blob = await api.document(`/api/v1/reports/${kind}?format=pdf`);
      return { kind, blob };
    },
    onSuccess: ({ kind, blob }) => {
      setFailure(null);
      saveBlob(blob, `cloudguard-${kind}-report.pdf`);
    },
    onError: (err) =>
      setFailure({
        // A server missing WeasyPrint's native libraries is an operator
        // problem, not something the reader can retry their way out of, so it
        // is named rather than folded into a generic failure.
        title:
          err instanceof ApiError && err.code === "NOT_CONFIGURED"
            ? t.reports.noPdfTitle
            : t.reports.failed,
        detail: err instanceof Error ? err.message : "Unknown error",
      }),
  });

  const preview = useMutation({
    mutationFn: async (kind: Kind) => api.document(`/api/v1/reports/${kind}?format=html`),
    onSuccess: (blob) => {
      setFailure(null);
      openBlob(blob);
    },
    onError: (err) =>
      setFailure({
        title: t.reports.failed,
        detail: err instanceof Error ? err.message : "Unknown error",
      }),
  });

  const busyKind = download.isPending ? download.variables : null;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader title={t.reports.title} description={t.reports.intro} />

      {failure && (
        <ErrorState
          title={failure.title}
          detail={failure.detail}
          impact="Nothing about your environment has changed — this is a problem producing the document."
        />
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <ReportCard
          title={t.reports.executive}
          detail={t.reports.executiveDetail}
          busy={busyKind === "executive"}
          disabled={download.isPending || preview.isPending}
          onDownload={() => download.mutate("executive")}
          onPreview={() => preview.mutate("executive")}
        />
        <ReportCard
          title={t.reports.technical}
          detail={t.reports.technicalDetail}
          busy={busyKind === "technical"}
          disabled={download.isPending || preview.isPending}
          onDownload={() => download.mutate("technical")}
          onPreview={() => preview.mutate("technical")}
        />
      </div>

      <p className="max-w-3xl text-xs leading-relaxed text-muted-foreground">
        {t.reports.freshNote}
      </p>
    </div>
  );
}

function ReportCard({
  title,
  detail,
  busy,
  disabled,
  onDownload,
  onPreview,
}: {
  title: string;
  detail: string;
  busy: boolean;
  disabled: boolean;
  onDownload: () => void;
  onPreview: () => void;
}) {
  const t = useT();

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <FileTextIcon className="size-4 text-muted-foreground" aria-hidden />
          <CardTitle className="text-sm">{title}</CardTitle>
        </div>
        <CardDescription className="leading-relaxed">{detail}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap gap-2">
        <Button disabled={disabled} onClick={onDownload}>
          {busy ? <Spinner data-icon="inline-start" /> : <DownloadIcon data-icon="inline-start" />}
          {busy ? t.reports.preparing : t.reports.download}
        </Button>
        {/* The same document, unprinted. Worth offering: a reader deciding
            whether to send this to a board should be able to read it first
            without a file landing in their downloads folder. */}
        <Button
          variant="secondary"
          disabled={disabled}
          onClick={onPreview}
          aria-label={`${t.reports.preview}: ${title}`}
        >
          <ExternalLinkIcon data-icon="inline-start" />
          {t.reports.preview}
        </Button>
      </CardContent>
    </Card>
  );
}

/**
 * Hand the blob to the browser as a download.
 *
 * The object URL is revoked rather than left behind: it pins the whole PDF in
 * memory for the life of the document, and a reader generating a few reports
 * would otherwise hold every one of them.
 */
function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function openBlob(blob: Blob): void {
  const url = URL.createObjectURL(blob);
  window.open(url, "_blank", "noopener,noreferrer");
  // Not revoked immediately: the new tab has not finished reading it yet.
  // A minute is far longer than a render and short enough that a session
  // spent previewing reports does not accumulate them.
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
