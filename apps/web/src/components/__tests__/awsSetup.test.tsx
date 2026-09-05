/**
 * Connecting AWS, where the flow differs from Azure's.
 *
 * Three differences, and all three would read as bugs if they were missed. AWS
 * has no consent step, so a rail with a permanently grey "Grant consent" row
 * would look like a flow stuck on something nobody is going to do. The artefact
 * is a stack rather than a template, so a button reading "Deploy to Azure"
 * would be pointing at the wrong console. And the external id has to be in
 * front of the customer *before* they deploy: they are about to create a trust
 * policy that requires it, and somebody who cannot see it cannot check that the
 * stack they ran actually asks for it.
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AccessPanel } from "@/components/connections/AccessPanel";
import { SetupRail } from "@/components/connections/setup/SetupRail";
import { StepDeploy } from "@/components/connections/setup/StepDeploy";
import type { CloudConnection } from "@/lib/types";

function connection(overrides: Partial<CloudConnection> = {}): CloudConnection {
  return {
    id: "c1",
    provider: "aws",
    name: "production",
    scope_type: "ORGANIZATION",
    scope_id: "111122223333",
    consent_status: "GRANTED",
    consented_at: "2026-09-01T10:00:00Z",
    rbac_verified_at: null,
    role_version: "v1",
    role_upgrade_available: false,
    role_required_version: "v1",
    degraded_categories: [],
    status: "PENDING",
    status_detail: null,
    deploy_stalled: false,
    subscriptions: [],
    template_url:
      "https://us-east-1.console.aws.amazon.com/cloudformation/home#/stacks/create/review",
    provider_ref: {
      role_arn: "arn:aws:iam::111122223333:role/CloudGuardScannerRole",
      external_id: "cg-2f8a1c9e4b6d7a3f5e0c",
    },
    ...overrides,
  } as CloudConnection;
}

function deployStep(overrides: Partial<CloudConnection> = {}) {
  return render(
    <StepDeploy
      connection={connection(overrides)}
      onRecheck={() => {}}
      rechecking={false}
      onDiscard={() => {}}
      discarding={false}
    />,
  );
}

describe("the AWS setup flow", () => {
  it("shows the external id before the customer deploys anything", () => {
    // The one thing that makes this integration safe is that the trust policy
    // demands a value only the customer and CloudGuard know. Hidden, it cannot
    // be checked.
    deployStep();

    expect(screen.getByText("cg-2f8a1c9e4b6d7a3f5e0c")).toBeInTheDocument();
    expect(screen.getByText(/not a password/i)).toBeInTheDocument();
  });

  it("sends the customer to CloudFormation rather than to Azure Portal", () => {
    deployStep();

    expect(screen.getByRole("link", { name: /launch stack/i })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /deploy to azure/i })).toBeNull();
  });

  it("does not offer an external id on an Azure connection", () => {
    // Azure keeps nothing per customer, so a blank row headed "Your external
    // id" would be describing something that does not exist.
    deployStep({
      provider: "azure",
      scope_type: "TENANT_ROOT",
      provider_ref: {},
      template_url: "https://portal.azure.com/#create/Microsoft.Template/uri/abc",
    });

    expect(screen.queryByText(/your external id/i)).toBeNull();
  });

  it("gives the rail three rows, not four", () => {
    render(<SetupRail stage="deploy" provider="aws" />);

    expect(screen.queryByText(/grants admin consent/i)).toBeNull();
    expect(screen.getByText(/deploy the scanner stack/i)).toBeInTheDocument();
  });

  it("states one grant on the access panel rather than two", () => {
    // A permanently green "Consent: granted" row beside a single AWS grant
    // would be describing a step that never happened.
    render(
      <AccessPanel
        connection={connection({ rbac_verified_at: "2026-09-01T10:05:00Z" })}
        onRecheck={() => {}}
        rechecking={false}
      />,
    );

    expect(screen.queryByText(/admin consent/i)).toBeNull();
    expect(screen.getByText(/scanner role/i)).toBeInTheDocument();
    expect(screen.getByText("cg-2f8a1c9e4b6d7a3f5e0c")).toBeInTheDocument();
  });
});
