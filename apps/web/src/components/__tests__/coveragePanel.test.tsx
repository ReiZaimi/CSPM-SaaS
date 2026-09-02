/**
 * The coverage card's hardest job is the part people act on: what could not be
 * collected, and why.
 *
 * Azure reports a failure per evidence key, so one missing admin consent
 * arrives as the same nine-hundred-character sentence three times over. Printed
 * verbatim it buried the one line worth reading under its own repetitions.
 */
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { CoveragePanel } from "@/components/dashboard/CoveragePanel";
import { groupCauses } from "@/lib/collectionErrors";

const CONSENT_FAILURE =
  "Access denied. Admin consent for CloudGuard's directory permissions is " +
  "missing or incomplete. A Global Administrator must grant it under Microsoft " +
  "Entra ID > Enterprise applications > CloudGuard > Permissions.";

describe("collection failures", () => {
  it("states one cause once, naming everything it cost", () => {
    const causes = groupCauses(
      `users: ${CONSENT_FAILURE}; directory_roles: ${CONSENT_FAILURE}; ` +
        "user_role_map: needs users, which did not produce usable data",
    );

    expect(causes).toHaveLength(2);
    expect(causes[0].keys).toEqual(["users", "directory_roles"]);
    expect(causes[1].keys).toEqual(["user_role_map"]);
  });

  it("never cuts a provider message in half on a semicolon of its own", () => {
    // Azure's text carries its own punctuation, and a reader searching for the
    // error they were given must find the whole of it.
    const causes = groupCauses(
      "users: Access denied; the tenant did not grant Directory.Read.All",
    );

    expect(causes).toHaveLength(1);
    expect(causes[0].message).toContain("did not grant Directory.Read.All");
  });

  it("clips a long message rather than filling the page with it", () => {
    render(
      <MemoryRouter>
        <CoveragePanel
          ratio={0.75}
          unknown={1}
          conclusive={3}
          gaps={[["identity", `users: ${CONSENT_FAILURE}`]]}
          freshness={null}
        />
      </MemoryRouter>,
    );

    expect(screen.getByText("1 category could not be collected")).toBeInTheDocument();
    // The provider's own words are kept, not paraphrased — just not all at once.
    expect(
      screen.getByRole("button", { name: "Show the whole message" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Access denied/)).toBeInTheDocument();
  });
});

describe("assets CloudGuard could not classify", () => {
  it("states what the score is not charging for, and what to do about it", () => {
    // The half of coverage the score used to spend silently. Missing evidence
    // never becomes a finding; missing context did reach the number, because an
    // unknown criticality ranks just under High so nothing hides behind a
    // missing label. That caution belongs to the ordering, not the posture.
    render(
      <MemoryRouter>
        <CoveragePanel
          ratio={1}
          unknown={0}
          conclusive={12}
          context={{ unclassified: 9, classified: 3, ratio: 0.25 }}
          freshness={null}
        />
      </MemoryRouter>,
    );

    expect(screen.getByText("9 of 12 open risks")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /Tell CloudGuard what these subscriptions hold/ }),
    ).toHaveAttribute("href", "/settings");
  });

  it("says nothing when every open risk sits on a classified asset", () => {
    // A panel that reported "0 unclassified" would be a line of noise on the
    // estates that did the work.
    render(
      <MemoryRouter>
        <CoveragePanel
          ratio={1}
          unknown={0}
          conclusive={12}
          context={{ unclassified: 0, classified: 12, ratio: 1 }}
          freshness={null}
        />
      </MemoryRouter>,
    );

    expect(screen.queryByText(/could not classify/)).not.toBeInTheDocument();
  });
});
