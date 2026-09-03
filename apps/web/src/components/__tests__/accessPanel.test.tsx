/**
 * The line that used to say a stale role was fine.
 *
 * A deployed role older than the one CloudGuard needs was printed in the same
 * green as a current one, because the version was rendered and never compared.
 * So a customer whose database and key vault checks were all reporting "not
 * known" had a screen telling them their access was verified, and nothing
 * anywhere in the product connected the two.
 *
 * The backend has known since role versions existed -- `role_upgrade_available`
 * was on the payload and unread. These tests are about it reaching somebody.
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AccessPanel } from "@/components/connections/AccessPanel";
import type { CloudConnection } from "@/lib/types";

function connection(overrides: Partial<CloudConnection> = {}): CloudConnection {
  return {
    consent_status: "GRANTED",
    consented_at: "2026-08-31T10:00:00Z",
    rbac_verified_at: "2026-08-31T10:05:00Z",
    role_version: "v4",
    role_upgrade_available: false,
    role_required_version: "v4",
    degraded_categories: [],
    template_url: "https://portal.azure.com/#create/Microsoft.Template/uri/abc",
    ...overrides,
  } as CloudConnection;
}

function mount(overrides: Partial<CloudConnection> = {}) {
  return render(
    <AccessPanel
      connection={connection(overrides)}
      onRecheck={() => {}}
      rechecking={false}
    />,
  );
}

describe("the access panel", () => {
  it("says a current role is verified, and when", () => {
    mount();

    expect(screen.getByText(/v4, verified/)).toBeInTheDocument();
    expect(
      screen.queryByText(/cannot run until the role is redeployed/i),
    ).not.toBeInTheDocument();
  });

  it("says a role is behind, and which one it should be", () => {
    mount({
      role_version: "v3",
      role_upgrade_available: true,
      role_required_version: "v4",
      degraded_categories: ["database"],
    });

    expect(screen.getByText(/v3, behind \(v4\)/)).toBeInTheDocument();
  });

  it("stops calling a stale role verified", () => {
    /** The defect itself. "verified" beside a role that cannot serve half the
     * catalogue is the sentence that kept a customer from ever looking. */
    mount({ role_version: "v3", role_upgrade_available: true });

    expect(screen.queryByText(/verified/)).not.toBeInTheDocument();
  });

  it("names the checks that are not running, rather than counting them", () => {
    /** "Two categories are degraded" is a number. "Databases, Key vaults" is
     * what tells somebody whether this is urgent for them. */
    mount({
      role_upgrade_available: true,
      degraded_categories: ["database", "secrets"],
    });

    expect(screen.getByText(/Databases, Key vaults/)).toBeInTheDocument();
  });

  it("says the affected checks report not-known rather than passing", () => {
    /** The product's own invariant, stated where it is felt. A customer who
     * assumed silence meant a pass would draw exactly the wrong conclusion. */
    mount({ role_upgrade_available: true });

    expect(screen.getByText(/not known/)).toBeInTheDocument();
  });

  it("offers the deployment link the setup wizard uses", () => {
    /** Redeploying is deploying again -- the template carries the current role
     * definition -- so a second route would be inventing one. */
    mount({ role_upgrade_available: true });

    const link = screen.getByRole("link", { name: /redeploy the role/i });
    expect(link).toHaveAttribute(
      "href",
      "https://portal.azure.com/#create/Microsoft.Template/uri/abc",
    );
  });

  it("offers no link when there is no template to deploy", () => {
    /** A connection whose deployment URL could not be built has nothing to
     * point at, and a dead button is worse than none. */
    mount({ role_upgrade_available: true, template_url: null });

    expect(
      screen.queryByRole("link", { name: /redeploy the role/i }),
    ).not.toBeInTheDocument();
  });

  it("still reports an unverified role as unverified", () => {
    /** Being behind and never having been granted are different problems with
     * different fixes, and the older state keeps its own wording. */
    mount({ rbac_verified_at: null, role_upgrade_available: true });

    expect(screen.getByText("Not verified")).toBeInTheDocument();
    expect(screen.queryByText(/behind/)).not.toBeInTheDocument();
  });

  it("still states that CloudGuard holds no write permission", () => {
    /** The product's central claim about itself. It sits on this panel, and a
     * new alert above it must not be what pushes it off the screen. */
    mount({ role_upgrade_available: true });

    expect(screen.getByText(/none, by design/i)).toBeInTheDocument();
  });
});
