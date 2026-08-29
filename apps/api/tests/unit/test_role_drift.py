"""What happens when a customer's deployed role falls behind the scanner.

``CloudConnection.role_version`` has been stamped at creation since connections
existed, and nothing ever read it back. That made it a label rather than a
mechanism: bumping ``ROLE_VERSION`` to ship a check needing a new ARM action
would leave every existing customer collecting UNKNOWN for it, with no prompt
and nothing on screen to explain why.

The tests that matter here are the two guards. One catches a version bumped
without recording what the old version granted -- without that record there is
no way to know which checks a deployed role cannot serve. The other catches a
collection category renamed out from under the explanation, which would leave
the drift silent again in a different way.
"""

import pytest

from app.connectors.azure import rbac
from app.connectors.azure.plan import AzurePlanBuilder
from app.connectors.azure.rbac import (
    ARM_READ_ACTIONS,
    COLLECTION_ACTIONS,
    ROLE_HISTORY,
    ROLE_VERSION,
    actions_missing_from,
    categories_behind,
    role_is_current,
)
from app.core.enums import CloudAccountStatus, ConnectionScope, ConsentStatus, Provider
from app.models.cloud_connection import CloudConnection
from app.services.cloud_connections import degraded_categories, role_upgrade_available


def build_test_plan():
    """The plan, built without touching Azure. ``build()`` only assembles
    closures -- nothing is called until the executor runs them."""
    import httpx

    return AzurePlanBuilder(
        tokens=object(), subscription_id="sub-1", http_client=httpx.AsyncClient()
    ).build()


def make_connection(role_version: str, provider: Provider = Provider.AZURE):
    return CloudConnection(
        provider=provider,
        name="test",
        scope_type=ConnectionScope.SUBSCRIPTION,
        scope_id="00000000-0000-0000-0000-000000000000",
        role_version=role_version,
        consent_status=ConsentStatus.GRANTED,
        status=CloudAccountStatus.ACTIVE,
    )


# --------------------------------------------------------------- the guards
def test_current_role_version_is_recorded_in_history() -> None:
    """Bumping ROLE_VERSION without recording its actions is the failure mode
    this whole mechanism exists to prevent, so it fails the build instead."""
    assert ROLE_VERSION in ROLE_HISTORY, (
        f"ROLE_VERSION is {ROLE_VERSION!r} but ROLE_HISTORY has no entry for it. "
        "Add one holding exactly the actions that version grants."
    )
    assert ROLE_HISTORY[ROLE_VERSION] == ARM_READ_ACTIONS


def test_every_historical_version_is_a_subset_of_today() -> None:
    """The role only ever grows. A past version granting something the current
    one does not would mean an action was dropped without a version bump."""
    for version, actions in ROLE_HISTORY.items():
        unknown = set(actions) - set(ARM_READ_ACTIONS)
        assert not unknown, f"role {version} grants actions no longer defined: {unknown}"


def test_a_superseded_version_granted_strictly_less_than_today() -> None:
    """The guard that was missing, and the reason this file gained a test.

    ``ROLE_HISTORY`` first shipped as ``{"v1": ARM_READ_ACTIONS}``, which binds
    the name rather than the value. Appending an action for v2 would have
    redefined v1 to match it, ``actions_missing_from("v1")`` would have returned
    nothing, and every existing customer would have been judged up to date --
    the whole mechanism quietly doing nothing.

    Equality with today's role is the signature of that mistake: a version that
    granted exactly what the current one grants is a version there was no
    reason to publish. The two guards above both passed while it was true, so
    this is the one that has to hold.
    """
    for version, actions in ROLE_HISTORY.items():
        if version == ROLE_VERSION:
            continue
        assert set(actions) < set(ARM_READ_ACTIONS), (
            f"role {version} grants exactly what {ROLE_VERSION} does. Either the "
            f"bump added nothing, or {version}'s entry is aliasing "
            "ARM_READ_ACTIONS instead of recording what it actually granted."
        )


def test_collection_actions_are_real_granted_actions() -> None:
    for category, actions in COLLECTION_ACTIONS.items():
        for action in actions:
            assert action in ARM_READ_ACTIONS, (
                f"{category} claims {action}, which the role does not grant"
            )


def test_collection_categories_match_the_plan() -> None:
    """The category names live in two files and a rename in one would silently
    orphan the drift explanation in the other."""
    planned = {task.category for task in build_test_plan()}

    assert planned, "could not build a collection plan"
    orphaned = set(COLLECTION_ACTIONS) - planned
    assert not orphaned, (
        f"COLLECTION_ACTIONS names categories the plan does not gather: {orphaned}"
    )


def test_every_planned_arm_action_is_granted_by_the_role() -> None:
    """A task declaring an action the role never asks for is a 403 waiting to
    happen inside one collection category, months after the code was written."""
    granted = set(ARM_READ_ACTIONS)
    for task in build_test_plan():
        for action in task.actions:
            assert action in granted, (
                f"task {task.key!r} needs {action}, which the scanner role does not grant"
            )


def test_every_collection_action_is_claimed_by_a_task() -> None:
    """The other direction. An action nothing asks for is a permission on a
    customer's consent screen that nothing has ever used."""
    claimed = {action for task in build_test_plan() for action in task.actions}
    for category, actions in COLLECTION_ACTIONS.items():
        for action in actions:
            assert action in claimed, (
                f"{category} declares {action}, which no collection task uses"
            )


# ------------------------------------------------------------ current role
def test_a_current_role_is_missing_nothing() -> None:
    assert actions_missing_from(ROLE_VERSION) == ()
    assert categories_behind(ROLE_VERSION) == frozenset()
    assert role_is_current(ROLE_VERSION)


def test_a_current_connection_prompts_no_upgrade() -> None:
    connection = make_connection(ROLE_VERSION)
    assert role_upgrade_available(connection) is False
    assert degraded_categories(connection) == {}


def test_an_unknown_role_version_is_treated_as_granting_nothing() -> None:
    """Fail-safe direction. Over-reporting a gap costs a redeploy prompt;
    under-reporting one costs silent UNKNOWNs the customer never hears about."""
    assert set(actions_missing_from("v-not-a-real-version")) == set(ARM_READ_ACTIONS)
    assert not role_is_current("v-not-a-real-version")


# ------------------------------------------------------------- a real drift
@pytest.fixture
def role_v2(monkeypatch: pytest.MonkeyPatch) -> None:
    """A future in which the role grew a storage action v1 never granted."""
    new_action = "Microsoft.Storage/storageAccounts/blobServices/read"
    grown = (*ARM_READ_ACTIONS, new_action)

    monkeypatch.setattr(rbac, "ARM_READ_ACTIONS", grown)
    monkeypatch.setattr(rbac, "ROLE_VERSION", "v2")
    monkeypatch.setattr(rbac, "ROLE_HISTORY", {"v1": ARM_READ_ACTIONS, "v2": grown})
    monkeypatch.setattr(
        rbac,
        "COLLECTION_ACTIONS",
        {**COLLECTION_ACTIONS, "storage": ("Microsoft.Storage/storageAccounts/read", new_action)},
    )


def test_an_older_role_is_behind_in_exactly_the_affected_category(role_v2: None) -> None:
    assert rbac.actions_missing_from("v1") == (
        "Microsoft.Storage/storageAccounts/blobServices/read",
    )
    assert rbac.categories_behind("v1") == frozenset({"storage"})


def test_drift_names_both_versions_and_says_what_to_do(
    role_v2: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The message replaces "403 Forbidden", so it has to carry the instruction."""
    monkeypatch.setattr("app.services.cloud_connections.ROLE_VERSION", "v2")
    connection = make_connection("v1")

    assert role_upgrade_available(connection) is True
    degraded = degraded_categories(connection)

    assert set(degraded) == {"storage"}
    message = degraded["storage"]
    assert "v1" in message and "v2" in message
    assert "redeploy" in message.lower()


def test_non_azure_connections_have_no_role_to_be_behind(role_v2: None) -> None:
    """The scanner calls this without knowing which cloud it is looking at."""
    connection = make_connection("v1", provider=Provider.AWS)
    assert role_upgrade_available(connection) is False
    assert degraded_categories(connection) == {}
