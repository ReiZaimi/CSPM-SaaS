import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { ScanDetail } from "@/lib/types";
import { useT } from "@/i18n";
import { Button } from "@/components/ui/button";

/**
 * Deleting a scan is two different acts, so it asks which.
 *
 * The record is an execution log. The findings it raised are statements about
 * the environment, which is why `findings.scan_id` is ON DELETE SET NULL --
 * history can be pruned without discarding what was found. Purging is for a run
 * whose results the user considers wrong, and never touches resolved findings:
 * each is the evidence that a fix was verified.
 *
 * Both options are spelled out with their consequence rather than offered as
 * "delete" and a checkbox. This is the one destructive action in the product
 * that can remove security findings, and the count of what would go is read
 * from the API rather than described in the abstract.
 */
export function DeleteScanConfirm({
  scanId,
  busy,
  onConfirm,
  onCancel,
}: {
  scanId: string;
  busy: boolean;
  onConfirm: (purge: boolean) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const detail = useQuery({
    queryKey: ["scan-detail", scanId],
    queryFn: () => api.get<ScanDetail>(`/api/v1/scans/${scanId}/detail`).then((r) => r.data),
  });
  const purgeable = detail.data?.purgeable_finding_count ?? 0;

  return (
    <div className="mt-3 rounded-lg border border-critical-border bg-critical-bg px-4 py-3">
      <p className="text-sm font-medium text-critical">{t.scans.deleteTitle}</p>
      <div className="mt-3 flex flex-col gap-2">
        <div>
          <Button variant="secondary" onClick={() => onConfirm(false)} disabled={busy}>
            {t.scans.deleteRecordOnly}
          </Button>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            {t.scans.deleteRecordOnlyDetail}
          </p>
        </div>
        <div>
          <Button variant="destructive" onClick={() => onConfirm(true)} disabled={busy}>
            {t.scans.deleteWithFindings}
            {purgeable > 0 && ` (${purgeable})`}
          </Button>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            {t.scans.deleteWithFindingsDetail}
          </p>
        </div>
      </div>
      <Button variant="ghost" className="mt-3" onClick={onCancel} disabled={busy}>
        {t.findings.cancel}
      </Button>
    </div>
  );
}
