import type { ConfigProblem } from "@/lib/config";

/**
 * Shown instead of the app when a production build is missing the environment
 * variables it needs. Deliberately plain HTML and inline-ish classes so it
 * cannot itself fail for a configuration reason.
 */
export function ConfigError({ problems }: { problems: ConfigProblem[] }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-stone-50 px-6 py-12">
      <div className="w-full max-w-xl rounded-xl border border-critical-border bg-white p-6 shadow-sm">
        <h1 className="text-lg font-semibold text-stone-900">
          CloudGuard is deployed but not configured
        </h1>
        <p className="mt-2 text-sm text-stone-600">
          The build is missing environment variables it needs to reach the API. Set these
          in your hosting provider (Vercel: Project Settings → Environment Variables),
          then <strong>redeploy</strong> — Vite reads these at build time, so changing
          them does not take effect until the next build.
        </p>

        <ul className="mt-5 space-y-4">
          {problems.map((problem) => (
            <li key={problem.variable}>
              <code className="text-sm font-semibold text-critical">{problem.variable}</code>
              <p className="mt-1 text-sm leading-relaxed text-stone-600">{problem.detail}</p>
            </li>
          ))}
        </ul>

        <p className="mt-6 border-t border-stone-100 pt-4 text-xs text-stone-500">
          Full walkthrough: <code>docs/DEPLOYMENT.md</code> in the repository.
        </p>
      </div>
    </div>
  );
}
