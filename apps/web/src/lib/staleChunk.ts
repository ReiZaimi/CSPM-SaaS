/**
 * Telling "a new version shipped" apart from "something is broken".
 *
 * Every page is a dynamic import, and a deploy replaces the hashed files a tab
 * already open was going to fetch. Somebody who leaves CloudGuard open, gets a
 * release, then clicks Findings asks for a chunk that no longer exists. That is
 * not a bug to report to anyone: it is a page that needs the new build.
 *
 * Its own module rather than a second export beside the boundary, so the
 * component file exports a component and nothing else -- which is what keeps
 * fast refresh working on it.
 */
export function isStaleChunkError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  // Every engine words it differently and none of them carry a code, so the
  // message is what there is. Matched loosely on purpose: a false positive
  // costs one reload, and a false negative costs a blank page.
  const text = `${error.name}: ${error.message}`.toLowerCase();
  return (
    text.includes("chunkloaderror") ||
    text.includes("dynamically imported module") ||
    text.includes("importing a module script failed") ||
    text.includes("error loading dynamically imported module")
  );
}
