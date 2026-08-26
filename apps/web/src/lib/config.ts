/**
 * Build-time configuration checks.
 *
 * Vite inlines `import.meta.env` at build time, so a bundle built without these
 * variables cannot reach the API at all — the app deploys green, loads fine,
 * and then every request fails with nothing to explain why. That is the worst
 * kind of failure: invisible to the deploy, baffling to the user. These checks
 * turn it into a readable message instead.
 *
 * There is no development exemption. CloudGuard has one deployment target, so
 * a build missing these is broken wherever it is running.
 */

export interface ConfigProblem {
  variable: string;
  detail: string;
}

export function configProblems(): ConfigProblem[] {
  const problems: ConfigProblem[] = [];

  if (!import.meta.env.VITE_API_URL) {
    problems.push({
      variable: "VITE_API_URL",
      detail:
        "Unset, so the app has no API to call. Set it to your deployed API's " +
        "public URL (Railway: your service's generated domain).",
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
        "Both unset, so there is no way to sign in. Set both from Supabase: " +
        "Project Settings > API. Use the anon/publishable key, never the " +
        "service_role key.",
    });
  } else if (hasUrl !== hasKey) {
    problems.push({
      variable: hasUrl ? "VITE_SUPABASE_PUBLISHABLE_KEY" : "VITE_SUPABASE_URL",
      detail: "Set one of the two Supabase variables but not the other. Set both.",
    });
  }

  return problems;
}
