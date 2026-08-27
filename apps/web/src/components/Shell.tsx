import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, auth } from "@/lib/api";
import { supabaseSignOut } from "@/lib/supabase";
import type { Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/format";
import { ShieldMark } from "@/components/Brand";

export function Shell() {
  const t = useT();
  const navigate = useNavigate();

  const { data: orgs, isLoading } = useQuery({
    queryKey: ["organizations"],
    queryFn: () => api.get<Organization[]>("/api/v1/organizations").then((r) => r.data),
  });

  // A signed-in user with no organization has not finished signing up.
  if (!isLoading && orgs && orgs.length === 0) {
    navigate("/onboarding", { replace: true });
  }

  const current = orgs?.find((o) => o.id === auth.organizationId) ?? orgs?.[0];
  if (current && auth.organizationId !== current.id) {
    auth.organizationId = current.id;
  }

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
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-3">
            <ShieldMark />
            <div>
              <p className="text-sm font-semibold tracking-tight">{t.app.name}</p>
              {current && <p className="text-xs text-stone-500">{current.name}</p>}
            </div>
          </div>
          <button
            onClick={() => {
              // Clears the local token immediately; the Supabase sign-out
              // (which also revokes the refresh token server-side) is fired
              // without blocking navigation on it.
              auth.signOut();
              void supabaseSignOut();
              navigate("/sign-in", { replace: true });
            }}
            className="text-sm text-stone-500 hover:text-stone-900"
          >
            {t.nav.signOut}
          </button>
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
