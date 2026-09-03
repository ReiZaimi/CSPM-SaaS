/**
 * Handing a generated document to the browser.
 *
 * Both of these existed inside the reports page, and the compliance export is
 * the second caller: a report and an audit export are the same problem --
 * bytes fetched with the caller's token, which a plain `<a href>` cannot do,
 * because the bearer token lives in memory rather than in a cookie and a
 * browser-initiated navigation would arrive unauthenticated.
 */

/** Hand the blob to the browser as a download.
 *
 * The object URL is revoked rather than left behind: it pins the whole file in
 * memory for the life of the document, and a reader generating a few exports
 * would otherwise hold every one of them.
 */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

/** Open the blob in a new tab, for a document meant to be read rather than kept. */
export function openBlob(blob: Blob): void {
  const url = URL.createObjectURL(blob);
  window.open(url, "_blank", "noopener,noreferrer");
  // Not revoked immediately: the new tab has not finished reading it yet.
  // A minute is far longer than a render and short enough that a session
  // spent previewing reports does not accumulate them.
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
