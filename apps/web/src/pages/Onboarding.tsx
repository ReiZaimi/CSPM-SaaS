import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { api, auth, ApiError } from "@/lib/api";
import type { Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";

/**
 * Step one of two: the organization every other row in the database hangs off.
 *
 * The form is a `FieldGroup` rather than stacked divs so the label, the control
 * and its description are one accessible unit -- which matters more here than
 * anywhere else in the product, because this is the first screen a new customer
 * ever fills in.
 */
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
      setError(
        err instanceof ApiError ? err.message : "Could not create organization",
      );
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/40 px-6">
      <div className="w-full max-w-md">
        <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {t.onboarding.step} 1 / 2
        </p>
        <h1 className="text-2xl font-semibold tracking-tight">
          {t.onboarding.createOrg}
        </h1>

        <form
          onSubmit={submit}
          className="mt-6 rounded-xl border bg-background p-6 shadow-sm"
        >
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="org-name">{t.onboarding.orgName}</FieldLabel>
              <Input
                id="org-name"
                required
                autoFocus
                minLength={2}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Acme sh.p.k."
              />
              <FieldDescription>
                Everything CloudGuard discovers is separated by organization.
              </FieldDescription>
            </Field>

            <Field>
              <FieldLabel htmlFor="org-industry">
                {t.onboarding.industry}
              </FieldLabel>
              <Input
                id="org-industry"
                value={industry}
                onChange={(e) => setIndustry(e.target.value)}
                placeholder="Financial services"
              />
            </Field>

            <Field>
              <FieldLabel htmlFor="org-country">
                {t.onboarding.country}
              </FieldLabel>
              <Input
                id="org-country"
                maxLength={2}
                value={country}
                onChange={(e) => setCountry(e.target.value.toUpperCase())}
                placeholder="AL"
              />
              <FieldDescription>
                Two-letter code, used for compliance context.
              </FieldDescription>
            </Field>

            {error && (
              <Alert variant="destructive">
                <AlertTitle>Could not create your organization</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button type="submit" disabled={busy} className="w-full">
              {busy && <Spinner data-icon="inline-start" />}
              {busy ? t.common.loading : t.onboarding.create}
            </Button>
          </FieldGroup>
        </form>
      </div>
    </div>
  );
}
