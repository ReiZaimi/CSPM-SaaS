import type { CloudConnection, ConnectionScope, Provider } from "@/lib/types";

/**
 * Where a connection has got to in setup.
 *
 * Derived from the connection rather than tracked in the wizard, because setup
 * leaves this application — once to the provider's consent screen where there
 * is one, and once to its console for the deployment — and a step number held
 * in React state does not survive either round trip. The server already knows:
 * consent is recorded by the callback, read access by the probe that runs on
 * every read of the connection. Asking it is the only answer that is still
 * right after the customer closes the tab and comes back tomorrow, or hands the
 * link to an administrator who opens it on another machine.
 */
export type SetupStage =
  /** Nothing created yet: the cloud, the name and the scope are still to be chosen. */
  | "scope"
  /** Created, waiting for an administrator to consent. Azure only. */
  | "consent"
  /** Waiting for the grant to appear at the chosen scope. */
  | "deploy"
  /** The grant is proven, but nothing has been found beneath the scope yet. */
  | "discover"
  /** Accounts found: choose which of them CloudGuard reads. */
  | "review"
  /** Verified, with at least one account in scope. */
  | "done"
  /** Setup was cancelled and can be resumed. */
  | "paused";

/**
 * Whether this cloud has a consent step separate from the deployment.
 *
 * Azure does: admin consent for Graph and an ARM role, granted by different
 * people at different moments. AWS does not — the stack *is* the grant. A
 * connection with no consent step must not sit on a "waiting for consent"
 * panel that nothing will ever advance, which is what this decides.
 */
export function hasConsentStep(provider: Provider): boolean {
  return provider === "azure";
}

export function connectionStage(connection: CloudConnection | null): SetupStage {
  if (!connection) return "scope";
  // Cancelled setup, not a disabled working connection: the difference is
  // whether it ever verified. Checked first, because a cancelled connection is
  // also un-consented and would otherwise report itself as waiting for an
  // administrator who is never going to be asked.
  if (connection.status === "DISABLED" && !connection.is_verified) return "paused";
  if (hasConsentStep(connection.provider) && connection.consent_status !== "GRANTED") {
    return "consent";
  }
  if (!connection.rbac_verified_at) return "deploy";
  if ((connection.subscriptions ?? []).length === 0) return "discover";
  if (!connection.is_ready_to_scan) return "review";
  return "done";
}

/**
 * Which sentence in the copy names this step.
 *
 * A literal union rather than `string`, so a rail rendering ``copy[step.key]``
 * is checked against the copy rather than trusted: a step naming a key nobody
 * wrote would otherwise render as an empty row.
 */
export type SetupStepKey = "stepScope" | "stepConsent" | "stepDeploy" | "stepAccounts";

type SetupStep = { stage: SetupStage; key: SetupStepKey };

/**
 * The things the customer is asked to do, in order.
 *
 * Four on Azure and three on AWS, and the difference is real rather than
 * cosmetic: a rail with a greyed-out "Grant consent" row that never lights up
 * reads as a flow that is stuck.
 *
 * Fewer rows than stages, because "discover", "review" and "done" are three
 * states of one step — looking at what was found — and a rail that grew a new
 * row when an account appeared would read as the finish line moving.
 */
export function setupSteps(provider: Provider): readonly SetupStep[] {
  const scope: SetupStep = { stage: "scope", key: "stepScope" };
  const deploy: SetupStep = { stage: "deploy", key: "stepDeploy" };
  const review: SetupStep = { stage: "review", key: "stepAccounts" };
  if (!hasConsentStep(provider)) return [scope, deploy, review];
  return [scope, { stage: "consent", key: "stepConsent" }, deploy, review];
}

/** Which row of the rail a stage lights up. */
export function stepIndex(stage: SetupStage, provider: Provider): number {
  const steps = setupSteps(provider);
  // A paused connection stopped somewhere, and the wizard shows that stage's
  // panel with a resume button on it. The rail points at the row it did before
  // the pause rather than at an extra "cancelled" one.
  const target: SetupStage = stage === "paused" ? "deploy" : stage;
  const found = steps.findIndex((step) => step.stage === target);
  // "discover" and "done" are not rows of their own: both belong to the last
  // one, which is where the customer is looking at what was found.
  return found === -1 ? steps.length - 1 : found;
}

/** True once the wizard has nothing left to ask for. */
export function isSetupComplete(connection: CloudConnection): boolean {
  return connection.is_ready_to_scan;
}

/** Where the wizard for a connection lives. */
export function setupPath(connectionId: string): string {
  return `/connections/${connectionId}/setup`;
}

/**
 * The scopes a cloud offers, widest first.
 *
 * The order is the coverage order in both clouds, and the trade is the same:
 * the widest sees every account that exists now or later and needs the broadest
 * grant, the narrowest is the least that works. CloudGuard does not pick.
 */
export function scopesFor(provider: Provider): ConnectionScope[] {
  return provider === "aws"
    ? ["ORGANIZATION", "ORGANIZATIONAL_UNIT", "ACCOUNT"]
    : ["TENANT_ROOT", "MANAGEMENT_GROUP", "SUBSCRIPTION"];
}

/**
 * Whether this scope has to name something the customer types.
 *
 * Azure's tenant root does not: its id is the tenant, and consent reports that.
 * AWS has no equivalent — there is nothing to assume a role *in* until an
 * account is named — so every AWS scope needs one, including the widest.
 */
export function needsScopeId(provider: Provider, scope: ConnectionScope): boolean {
  return provider === "aws" || scope !== "TENANT_ROOT";
}
