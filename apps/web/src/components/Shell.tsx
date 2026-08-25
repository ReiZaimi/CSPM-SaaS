import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, auth } from "@/lib/api";
import { supabaseSignOut } from "@/lib/supabase";
import type { Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/format";

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

function ShieldMark() {
  return (
    <svg viewBox="0 0 24 24" className="h-7 w-7 text-stone-900" aria-hidden="true">
      <path
        fill="currentColor"
        d="M12 2 4 5.5v6c0 4.6 3.2 8.9 8 10.5 4.8-1.6 8-5.9 8-10.5v-6L12 2Z"
        opacity="0.12"
      />
      <path
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
        d="M12 2.9 4.8 6.1v5.4c0 4.2 2.9 8.1 7.2 9.6 4.3-1.5 7.2-5.4 7.2-9.6V6.1L12 2.9Z"
      />
      <path
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
        d="m8.8 12.2 2.2 2.2 4.2-4.4"
      />
    </svg>
  );
}
