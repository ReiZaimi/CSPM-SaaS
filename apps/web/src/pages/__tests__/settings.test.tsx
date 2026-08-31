/**
 * Settings: the half of CloudGuard's evidence that a person supplies.
 *
 * Two things must survive here. A context declaration is a *statement* — it is
 * replaced whole, and an unset field withdraws a claim rather than declaring
 * the value unknown. And UNKNOWN is never offered: it is CloudGuard's own word
 * for "nothing said anything", so a menu item for it would let a customer
 * assert an absence that saying nothing already asserts — and the API rejects
 * it, so the option would always fail.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SettingsPage } from "../Settings";
import { api } from "@/lib/api";
import type { CloudAccount, ContextDeclaration, Organization } from "@/lib/types";

function organization(overrides: Partial<Organization> = {}): Organization {
  return {
    id: "o-1",
    name: "Contoso",
    slug: "contoso-a1b2c3",
    industry: "Banking",
    country: "AL",
    created_at: "2026-01-01T00:00:00Z",
    role: "OWNER",
    ...overrides,
  };
}

function account(overrides: Partial<CloudAccount> = {}): CloudAccount {
  return {
    id: "a-1",
    provider: "azure",
    account_name: "Production subscription",
    tenant_id: "t-1",
    subscription_id: "sub-1",
    consent_status: "GRANTED",
    rbac_verified_at: "2026-08-01T00:00:00Z",
    status: "ACTIVE",
    status_detail: null,
    last_scan_at: null,
    is_scannable: true,
    ...overrides,
  };
}

function mount({
  orgs = [organization()],
  accounts = [account()],
  declaration = null as ContextDeclaration | null,
}: {
  orgs?: Organization[];
  accounts?: CloudAccount[];
  declaration?: ContextDeclaration | null;
} = {}) {
  vi.spyOn(api, "get").mockImplementation((path: string) => {
    if (path.includes("/context")) {
      return Promise.resolve({ data: declaration, meta: {} }) as never;
    }
    if (path.includes("cloud-accounts")) {
      return Promise.resolve({ data: accounts, meta: {} }) as never;
    }
    return Promise.resolve({ data: orgs, meta: {} }) as never;
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <SettingsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("SettingsPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the organization as it currently describes itself", async () => {
    mount();

    await waitFor(() => expect(screen.getByLabelText("Name")).toHaveValue("Contoso"));
    expect(screen.getByLabelText("Industry")).toHaveValue("Banking");
    expect(screen.getByLabelText("Country")).toHaveValue("AL");
  });

  it("never lets the identifier be edited, and says why", async () => {
    mount();

    await waitFor(() => expect(screen.getByLabelText("Identifier")).toBeDisabled());
    expect(screen.getByText(/unchanged by a rename/)).toBeInTheDocument();
  });

  it("saves an edited name without clearing what was not touched", async () => {
    const patch = vi
      .spyOn(api, "patch")
      .mockResolvedValue({ data: organization({ name: "Contoso Group" }), meta: {} });
    mount();

    const name = await screen.findByLabelText("Name");
    fireEvent.change(name, { target: { value: "Contoso Group" } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() =>
      expect(patch).toHaveBeenCalledWith("/api/v1/organizations", {
        name: "Contoso Group",
        industry: "Banking",
        country: "AL",
      }),
    );
  });

  it("tells a reader who cannot edit why, rather than greying the fields silently", async () => {
    mount({ orgs: [organization({ role: "VIEWER" })] });

    await waitFor(() =>
      expect(screen.getByText(/Your role can read this but not change it/)).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: "Save changes" })).not.toBeInTheDocument();
  });

  // --- context declarations ------------------------------------------------

  it("lets a subscription be declared, which is what the risk engine multiplies by", async () => {
    const put = vi.spyOn(api, "put").mockResolvedValue({
      data: {
        cloud_account_id: "a-1",
        environment: "production",
        criticality: "HIGH",
        data_sensitivity: null,
        note: null,
        declared_by_user_id: "u-1",
        declared_at: "2026-08-31T09:00:00Z",
      },
      meta: {},
    });
    mount();

    fireEvent.change(await screen.findByLabelText("Environment"), {
      target: { value: "production" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save declaration" }));

    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/v1/cloud-accounts/a-1/context", {
        environment: "production",
        criticality: null,
        data_sensitivity: null,
        note: null,
      }),
    );
  });

  it("does not offer UNKNOWN as something a customer can declare", async () => {
    mount();

    fireEvent.click(await screen.findByRole("combobox", { name: "Criticality" }));

    await waitFor(() => expect(screen.getByText("Not declared")).toBeInTheDocument());
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.queryByText("Unknown")).not.toBeInTheDocument();
  });

  it("seeds the form from an existing declaration rather than showing it as undeclared", async () => {
    mount({
      declaration: {
        cloud_account_id: "a-1",
        environment: "production",
        criticality: "HIGH",
        data_sensitivity: "CRITICAL",
        note: "Holds cardholder data",
        declared_by_user_id: "u-1",
        declared_at: "2026-08-31T09:00:00Z",
      },
    });

    await waitFor(() =>
      expect(screen.getByLabelText("Environment")).toHaveValue("production"),
    );
    expect(screen.getByLabelText("Note")).toHaveValue("Holds cardholder data");
  });

  it("offers to withdraw a declaration only where there is one", async () => {
    mount();

    await screen.findByLabelText("Environment");
    // Nothing declared: a clear button here would do nothing and imply it might.
    expect(screen.queryByRole("button", { name: "Clear declaration" })).not.toBeInTheDocument();
  });

  it("says that an unset field is not a declaration of unknown", async () => {
    mount();

    await waitFor(() =>
      expect(
        screen.getByText(/not the same as declaring it unknown/),
      ).toBeInTheDocument(),
    );
  });

  it("says a declaration is not retroactive", async () => {
    // A customer who expects existing scores to move would otherwise read the
    // unchanged dashboard as a bug.
    mount();

    await waitFor(() =>
      expect(screen.getByText(/Applied by the next evaluation/)).toBeInTheDocument(),
    );
  });

  // --- deletion ------------------------------------------------------------

  it("refuses to delete until the organization is named", async () => {
    mount();

    const button = await screen.findByRole("button", { name: "Delete organization" });
    expect(button).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Type the organization name to confirm"), {
      target: { value: "Contoso" },
    });
    expect(button).toBeEnabled();
  });

  it("does not offer deletion to anyone but an owner", async () => {
    mount({ orgs: [organization({ role: "ADMIN" })] });

    await waitFor(() =>
      expect(screen.getByText("Only an owner can delete an organization.")).toBeInTheDocument(),
    );
    expect(
      screen.queryByRole("button", { name: "Delete organization" }),
    ).not.toBeInTheDocument();
  });
});
