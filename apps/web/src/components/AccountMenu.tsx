import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, auth } from "@/lib/api";
import { supabaseSignOut } from "@/lib/supabase";
import { useAuthEmail } from "@/lib/useAuth";
import type { Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { Button } from "@/components/ui";
import { cn, label } from "@/lib/format";

/**
 * The account menu.
 *
 * It exists mostly for the organization switcher. `auth.organizationId` has
 * always been read on every request as the `X-Organization-Id` header, but
 * nothing in the product could ever change it — so a user who belonged to two
 * organizations was permanently stuck in whichever one came back first. That
 * is a real capability, not a cosmetic one, which is why it gets a section of
 * its own rather than a line in a list.
 *
 * Switching clears the query cache. Cache keys do not include the organization
 * (the server derives the tenant, the client never names it in a URL), so
 * without the clear the new organization would render the previous one's
 * findings until each query happened to refetch.
 */
export function AccountMenu({
  organizations,
  current,
}: {
  organizations: Organization[];
  current: Organization | undefined;
}) {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const email = useAuthEmail();
  const [open, setOpen] = useState(false);
  // The organization the menu is currently asking about deleting. Held here
  // rather than as a boolean so the confirmation can name it -- "remove
  // Acme sh.p.k." is a different question from "remove organization".
  const [confirming, setConfirming] = useState<Organization | null>(null);
  const container = useRef<HTMLDivElement>(null);

  const removeOrg = useMutation({
    mutationFn: (organization: Organization) =>
      api.del(`/api/v1/organizations/${organization.id}`),
    onSuccess: (_result, organization) => {
      setConfirming(null);
      setOpen(false);
      // If the deleted one was selected, drop the stale preference before any
      // refetch: requests carry it as a header, and it now names nothing.
      if (auth.organizationId === organization.id) auth.organizationId = null;
      queryClient.clear();
      navigate("/", { replace: true });
    },
  });

  // Close on an outside click or Escape. Both are bound only while the menu is
  // open, so a closed menu costs nothing.
  useEffect(() => {
    if (!open) return;

    function onPointerDown(event: MouseEvent) {
      if (!container.current?.contains(event.target as Node)) setOpen(false);
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }

    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  useEffect(() => {
    if (!open) setConfirming(null);
  }, [open]);

  function switchTo(organization: Organization) {
    setOpen(false);
    if (organization.id === current?.id) return;
    auth.organizationId = organization.id;
    queryClient.clear();
    navigate("/", { replace: true });
  }

  function signOut() {
    setOpen(false);
    // Clears the local token immediately; the Supabase sign-out (which also
    // revokes the refresh token server-side) is fired without blocking
    // navigation on it.
    auth.signOut();
    queryClient.clear();
    void supabaseSignOut();
    navigate("/sign-in", { replace: true });
  }

  return (
    <div className="relative" ref={container}>
      <button
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={t.account.menu}
        className={cn(
          "flex items-center gap-2 rounded-lg border px-2 py-1.5 text-sm transition",
          open
            ? "border-input bg-muted/40"
            : "border-transparent hover:border-border hover:bg-muted/40",
        )}
      >
        <Avatar name={current?.name ?? email ?? "?"} />
        <span className="hidden max-w-[12rem] truncate font-medium text-foreground sm:block">
          {current?.name ?? t.account.unknownUser}
        </span>
        <Chevron open={open} />
      </button>

      {open && (
        <div
          role="menu"
          className="absolute right-0 z-20 mt-2 w-72 overflow-hidden rounded-xl border border-border bg-background shadow-lg"
        >
          <Section label={t.account.signedInAs}>
            <p className="truncate px-3 pb-2 text-sm font-medium text-foreground">
              {email ?? t.account.unknownUser}
            </p>
          </Section>

          {confirming ? (
            <Section label={t.account.removeOrgTitle}>
              <div className="px-3 pb-2">
                <p className="text-sm font-medium text-critical">
                  {t.account.removeOrgTitle} {confirming.name}?
                </p>
                <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                  {t.account.removeOrgDetail}
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <Button
                    variant="danger"
                    onClick={() => removeOrg.mutate(confirming)}
                    disabled={removeOrg.isPending}
                  >
                    {removeOrg.isPending ? t.account.removingOrg : t.account.removeOrg}
                  </Button>
                  <Button variant="secondary" onClick={() => setConfirming(null)}>
                    {t.account.keep}
                  </Button>
                </div>
                {removeOrg.isError && (
                  <p className="mt-2 text-xs text-critical">{t.common.error}</p>
                )}
              </div>
            </Section>
          ) : (
          <Section label={t.account.organization}>
            <ul>
              {organizations.map((organization) => (
                <li key={organization.id}>
                  <button
                    role="menuitem"
                    onClick={() => switchTo(organization)}
                    className="flex w-full items-center gap-2.5 px-3 py-2 text-left transition hover:bg-muted/40"
                  >
                    <Avatar name={organization.name} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm text-foreground">
                        {organization.name}
                      </span>
                      {organization.role && (
                        <span className="block text-xs text-muted-foreground">
                          {label(organization.role)}
                        </span>
                      )}
                    </span>
                    {organization.id === current?.id && (
                      <Check className="shrink-0 text-ok" />
                    )}
                  </button>
                </li>
              ))}
            </ul>

            {/* Owner-only, and acting on the *current* organization: deleting
                one you are not looking at is a mistake waiting to happen. */}
            {current?.role === "OWNER" && (
              <button
                role="menuitem"
                onClick={() => setConfirming(current)}
                className="mt-1 w-full px-3 py-2 text-left text-sm text-critical transition hover:bg-critical-bg"
              >
                {t.account.removeOrg}
                <span className="ml-1 text-muted-foreground">· {current.name}</span>
              </button>
            )}
          </Section>
          )}

          <div className="border-t border-border p-1">
            <button
              role="menuitem"
              onClick={signOut}
              className="w-full rounded-lg px-3 py-2 text-left text-sm text-foreground transition hover:bg-muted/40 hover:text-foreground"
            >
              {t.nav.signOut}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function Section({ label: text, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="border-b border-border py-2 last:border-b-0">
      <p className="px-3 pb-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        {text}
      </p>
      {children}
    </div>
  );
}

/** An initial rather than a photo: CloudGuard holds no avatar for anyone. */
function Avatar({ name }: { name: string }) {
  return (
    <span
      aria-hidden="true"
      className="flex size-6 shrink-0 items-center justify-center rounded-md bg-primary text-[11px] font-semibold text-primary-foreground"
    >
      {name.trim().charAt(0).toUpperCase() || "?"}
    </span>
  );
}

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      viewBox="0 0 20 20"
      className={cn(
        "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform",
        open && "rotate-180",
      )}
      aria-hidden="true"
    >
      <path
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
        d="m5 7.5 5 5 5-5"
      />
    </svg>
  );
}

function Check({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" className={cn("h-4 w-4", className)} aria-hidden="true">
      <path
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        d="m3.5 8.5 3 3 6-7"
      />
    </svg>
  );
}
