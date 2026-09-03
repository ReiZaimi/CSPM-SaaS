import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { DownloadIcon, ExternalLinkIcon, FileTextIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { openBlob, saveBlob } from "@/lib/download";
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
import { Checkbox } from "@/components/ui/checkbox";
import { SelectField } from "@/components/common/SelectField";
import { Spinner } from "@/components/ui/spinner";

type Kind = "executive" | "technical";

/**
 * What a reader can leave out, and what they cannot.
 *
 * The posture block and the evidence caveats are absent from this list on
 * purpose: a report that could drop "12% of checks reached no verdict" would
 * let somebody produce a cleaner-looking document by unticking a box. What is
 * optional is detail, never the terms the numbers are read on.
 */
type Section = {
  id: string;
  label: string;
  detail: string;
  /** Only meaningful in the technical report, which is the one that lists them. */
  technicalOnly?: boolean;
};

const SECTIONS: Section[] = [
  {
    id: "top_risks",
    label: "Top risks",
    detail: "Ranked by what a finding means on the asset it was found on.",
  },
  {
    id: "attack_paths",
    label: "Attack paths",
    detail: "Routes from something exposed to something worth taking, and the link to cut.",
  },
  {
    id: "remediation",
    label: "Remediation progress",
    detail: "Work claimed and fixes proved, reported separately.",
  },
  {
    id: "compliance",
    label: "Compliance coverage",
    detail: "Evidence toward each framework — never a verdict.",
  },
  {
    id: "findings",
    label: "Full findings list",
    detail: "Every open finding, worst first. Technical report only.",
    technicalOnly: true,
  },
];

/** The activity window. Not a filter on the posture — see the note by it. */
const WINDOWS = [30, 90, 365] as const;

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
  const [days, setDays] = useState<number>(30);
  const [chosen, setChosen] = useState<string[]>(SECTIONS.map((section) => section.id));

  /**
   * The options, as the API takes them.
   *
   * `sections` is always sent, including when it is empty: an absent parameter
   * means "all of them" and an empty one means "none", and collapsing the two
   * would make unticking every box produce the fullest document.
   */
  function query(kind: Kind, format: "pdf" | "html"): string {
    const applicable = chosen.filter(
      (id) =>
        kind === "technical" ||
        !SECTIONS.find((section) => section.id === id)?.technicalOnly,
    );
    const params = new URLSearchParams();
    params.set("format", format);
    params.set("days", String(days));
    params.set("sections", applicable.join(","));
    return params.toString();
  }

  function toggle(id: string, on: boolean) {
    setChosen((current) =>
      on ? [...new Set([...current, id])] : current.filter((item) => item !== id),
    );
  }

  const download = useMutation({
    mutationFn: async (kind: Kind) => {
      const blob = await api.document(`/api/v1/reports/${kind}?${query(kind, "pdf")}`);
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
    mutationFn: async (kind: Kind) =>
      api.document(`/api/v1/reports/${kind}?${query(kind, "html")}`),
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

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">What to include</CardTitle>
          <CardDescription>
            Both documents always carry the posture, how old the evidence is and
            what could not be read. Those are the terms the numbers are read on,
            so they are not optional.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-5">
          <div className="flex flex-wrap items-start gap-x-6 gap-y-2">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">Activity window</span>
              <SelectField
                value={String(days)}
                onValueChange={(value) => setDays(Number(value))}
                ariaLabel="Activity window"
                className="w-[150px]"
                options={WINDOWS.map((window) => ({
                  value: String(window),
                  label: `Last ${window} days`,
                }))}
              />
            </div>
            <p className="max-w-xl text-xs leading-relaxed text-muted-foreground">
              Sets how far back verified fixes, completed work and the trend line
              reach. It does not filter the posture: a score is a reading of now,
              not a thing that has a date range.
            </p>
          </div>

          <ul className="grid gap-2 sm:grid-cols-2">
            {SECTIONS.map((section) => (
              <li key={section.id} className="flex items-start gap-2.5">
                {/* Labelled by the visible text rather than wrapped in a
                    <label>: the primitive renders a button, and a button
                    inside a label is a click the browser delivers twice. */}
                <Checkbox
                  className="mt-0.5"
                  aria-labelledby={`section-${section.id}-label`}
                  checked={chosen.includes(section.id)}
                  onCheckedChange={(value) => toggle(section.id, value === true)}
                />
                <div>
                  <span
                    id={`section-${section.id}-label`}
                    className="block text-sm text-foreground"
                  >
                    {section.label}
                  </span>
                  <span className="block text-xs leading-snug text-muted-foreground">
                    {section.detail}
                  </span>
                </div>
              </li>
            ))}
          </ul>

          {/* Said here rather than discovered on the cover page: a section
              left out is named in the document, so nobody reads an omission
              somebody chose as an absence of evidence. */}
          <p className="text-xs leading-relaxed text-muted-foreground">
            Anything left unticked is named on the report's cover as excluded,
            so a reader downstream can tell a choice from a gap.
          </p>
        </CardContent>
      </Card>

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
