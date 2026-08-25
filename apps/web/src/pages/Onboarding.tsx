import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, auth, ApiError } from "@/lib/api";
import type { Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { Button, Field, Input } from "@/components/ui";

export function OnboardingPage() {
  const t = useT();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [industry, setIndustry] = useState("");
  const [country, setCountry] = useState("AL");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { data } = await api.post<Organization>("/api/v1/organizations", {
        name,
        industry: industry || null,
        country: country || null,
      });
      auth.organizationId = data.id;
      navigate("/connections", { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create organization");
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-stone-50 px-6">
      <div className="w-full max-w-md">
        <p className="mb-2 text-xs font-medium uppercase tracking-wide text-stone-400">
          {t.onboarding.step} 1 / 2
        </p>
        <h1 className="text-2xl font-semibold tracking-tight">{t.onboarding.createOrg}</h1>

        <form
          onSubmit={submit}
          className="mt-6 space-y-4 rounded-xl border border-stone-200 bg-white p-6 shadow-sm"
        >
          <Field label={t.onboarding.orgName}>
            <Input
              required
              autoFocus
              minLength={2}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Acme sh.p.k."
            />
          </Field>
          <Field label={t.onboarding.industry}>
            <Input
              value={industry}
              onChange={(e) => setIndustry(e.target.value)}
              placeholder="Financial services"
            />
          </Field>
          <Field label={t.onboarding.country}>
            <Input
              maxLength={2}
              value={country}
              onChange={(e) => setCountry(e.target.value.toUpperCase())}
              placeholder="AL"
            />
          </Field>

          {error && <p className="text-sm text-critical">{error}</p>}

          <Button type="submit" disabled={busy} className="w-full">
            {busy ? t.common.loading : t.onboarding.create}
          </Button>
        </form>
      </div>
    </div>
  );
}
