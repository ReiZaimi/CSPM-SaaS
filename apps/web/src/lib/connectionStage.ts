import type { CloudConnection } from "@/lib/types";

/**
 * Where a connection has got to in setup.
 *
 * Derived from the connection rather than tracked in the wizard, because setup
 * leaves this application twice -- once to Microsoft for admin consent, once to
 * Azure Portal for the role deployment -- and a step number held in React state
 * does not survive either round trip. The server already knows: consent is
 * recorded by the callback, read access by the probe that runs on every read of
 * the connection. Asking it is the only answer that is still right after the
 * customer closes the tab and comes back tomorrow, or hands the consent link to
 * an administrator who opens it on another machine.
 */
export type SetupStage =
  /** Nothing created yet: the name and the scope have still to be chosen. */
  | "scope"
  /** Created, waiting for a Global Administrator to consent. */
  | "consent"
  /** Consented, waiting for the reader role to appear at the chosen scope. */
  | "deploy"
  /** Both grants proven, but nothing has been found beneath the scope yet. */
  | "discover"
  /** Subscriptions found: choose which of them CloudGuard reads. */
  | "review"
  /** Verified, with at least one subscription in scope. */
  | "done"
  /** Setup was cancelled and can be resumed. */
  | "paused";

export function connectionStage(connection: CloudConnection | null): SetupStage {
  if (!connection) return "scope";
  // Cancelled setup, not a disabled working connection: the difference is
  // whether it ever verified. Checked first, because a cancelled connection is
  // also un-consented and would otherwise report itself as waiting for an
  // administrator who is never going to be asked.
  if (connection.status === "DISABLED" && !connection.is_verified) return "paused";
  if (connection.consent_status !== "GRANTED") return "consent";
  if (!connection.rbac_verified_at) return "deploy";
  if ((connection.subscriptions ?? []).length === 0) return "discover";
  if (!connection.is_ready_to_scan) return "review";
  return "done";
}

/**
 * The four things the customer is asked to do, in order.
 *
 * Four rather than one per stage: "discover", "review" and "done" are three
 * states of the same step -- looking at what was found -- and a rail that grew
 * a new row when a subscription appeared would read as the finish line moving.
 */
export const SETUP_STEPS = [
  { stage: "scope", key: "stepScope" },
  { stage: "consent", key: "stepConsent" },
  { stage: "deploy", key: "stepDeploy" },
  { stage: "review", key: "stepSubscriptions" },
] as const satisfies readonly { stage: SetupStage; key: string }[];

/** Which of the four rows in the rail a stage lights up. */
export function stepIndex(stage: SetupStage): number {
  switch (stage) {
    case "scope":
      return 0;
    case "consent":
      return 1;
    case "deploy":
      return 2;
    // A paused connection stopped somewhere, and the wizard shows that stage's
    // panel with a resume button on it. The rail points at the same row it did
    // before the pause rather than at a fifth "cancelled" one.
    case "paused":
      return 1;
    default:
      return 3;
  }
}

/** True once the wizard has nothing left to ask for. */
export function isSetupComplete(connection: CloudConnection): boolean {
  return connection.is_ready_to_scan;
}

/** Where the wizard for a connection lives. */
export function setupPath(connectionId: string): string {
  return `/connections/${connectionId}/setup`;
}
