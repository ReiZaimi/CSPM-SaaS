import { useEffect } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, auth } from "@/lib/api";
import type { Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/format";
import { ShieldMark } from "@/components/Brand";
import { AccountMenu } from "@/components/AccountMenu";

export function Shell() {
  const t = useT();
  const navigate = useNavigate();

  const { data: orgs, isLoading } = useQuery({
    queryKey: ["organizations"],
    queryFn: () => api.get<Organization[]>("/api/v1/organizations").then((r) => r.data),
  });

  // Both of these used to run during render, which meant navigating and writing
  // to a store that notifies subscribers while React was still rendering. It
  // mostly worked, and it stopped mostly working the moment the account menu
  // could change the selected organization: the write triggered a re-render
  // from inside a render.
  useEffect(() => {
    if (isLoading || !orgs) return;

    // A signed-in user with no organization has not finished signing up.
    if (orgs.length === 0) {
      navigate("/onboarding", { replace: true });
      return;
    }

    // Only default when the stored choice names nothing real — otherwise this
    // would immediately undo whatever the user just picked.
    const selected = orgs.find((o) => o.id === auth.organizationId);
    if (!selected) auth.organizationId = orgs[0].id;
  }, [isLoading, orgs, navigate]);

  const current = orgs?.find((o) => o.id === auth.organizationId) ?? orgs?.[0];

  const links = [
    { to: "/", label: t.nav.dashboard, end: true },
    { to: "/assets", label: t.nav.assets },
    { to: "/findings", label: t.nav.findings },
    { to: "/risks", label: t.nav.risks },
    { to: "/remediation", label: t.nav.remediation },
    { to: "/scans", label: t.nav.scans },
    { to: "/rules", label: t.nav.rules },
    { to: "/compliance", label: t.nav.compliance },
    { to: "/connections", label: t.nav.connections },
  ];

  return (
    <div className="min-h-screen">
      <header className="border-b border-stone-200 bg-white">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-6 py-3">
          <div className="flex items-center gap-3">
            <ShieldMark />
            {/* The organization used to be named here as well. It moved into
                the account menu, which is where switching it now lives — two
                places showing it invited the reading that they were different
                things. */}
            <p className="text-sm font-semibold tracking-tight">{t.app.name}</p>
          </div>

          <AccountMenu organizations={orgs ?? []} current={current} />
        </div>
        <nav className="mx-auto flex max-w-7xl gap-1 overflow-x-auto px-4">
          {links.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.end}
              className={({ isActive }) =>
                cn(
                  "whitespace-nowrap border-b-2 px-3 py-2.5 text-sm transition-colors",
                  isActive
                    ? "border-stone-900 font-medium text-stone-900"
                    : "border-transparent text-stone-500 hover:text-stone-900",
                )
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}
