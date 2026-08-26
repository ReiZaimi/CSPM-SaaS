/**
 * Build-time configuration checks.
 *
 * Vite inlines `import.meta.env` at build time, so a production bundle built
 * without VITE_API_URL silently falls back to localhost:8000 — the app deploys
 * green, loads fine, and then every request fails against a machine that isn't
 * there. That is the worst kind of failure: invisible to the deploy, confusing
 * to the user. These checks turn it into a readable message instead.
 */

export interface ConfigProblem {
  variable: string;
  detail: string;
}

export function configProblems(): ConfigProblem[] {
  // Only meaningful for a production bundle. Local dev intentionally runs on
  // the localhost fallbacks and the dev-token sign-in route.
  if (!import.meta.env.PROD) return [];

  const problems: ConfigProblem[] = [];

  if (!import.meta.env.VITE_API_URL) {
    problems.push({
      variable: "VITE_API_URL",
      detail:
        "Unset, so the app is calling http://localhost:8000 from your visitors' " +
        "browsers. Set it to your deployed API's public URL.",
    });
  }

  // Both Supabase values or neither. Half-configured means the sign-in button
  // silently does nothing, which is harder to diagnose than a clear message.
  const hasUrl = Boolean(import.meta.env.VITE_SUPABASE_URL);
  const hasKey = Boolean(import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY);

  if (!hasUrl && !hasKey) {
    problems.push({
      variable: "VITE_SUPABASE_URL / VITE_SUPABASE_PUBLISHABLE_KEY",
      detail:
        "Both unset, so there is no way to sign in — the local dev-token route " +
        "does not exist on a deployed API. Set both from Supabase: Project " +
        "Settings > API.",
    });
  } else if (hasUrl !== hasKey) {
    problems.push({
      variable: hasUrl ? "VITE_SUPABASE_PUBLISHABLE_KEY" : "VITE_SUPABASE_URL",
      detail: "Set one of the two Supabase variables but not the other. Set both.",
    });
  }

  return problems;
}
