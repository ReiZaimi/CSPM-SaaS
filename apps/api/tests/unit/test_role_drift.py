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

import itertools
import uuid
from datetime import UTC, datetime

import pytest

from app.api.routes import cloud_connections as routes
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
from app.connectors.evidence import EvidenceCategory
from app.core.enums import CloudAccountStatus, ConnectionScope, ConsentStatus, Provider
from app.models.cloud_connection import CloudConnection
from app.services.cloud_connections import degraded_categories, role_upgrade_available


def build_test_plan():
    """The plan, built without touching Azure. ``build()`` only assembles
    closures -- nothing is called until the executor runs them."""
    import httpx

    return AzurePlanBuilder(
        tokens=object(), subscription_id="sub-1", http_client=httpx.AsyncClient()
    ).build_account_plan()


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


# ------------------------------------------------------- the versions after v2
class TestRoleUpgrades:
    """Each new action becomes a redeploy prompt, not a 403 in one category.

    The whole point of ``ROLE_HISTORY`` is that a customer's deployed role is
    whatever it was on the day they deployed it. A check that needs a new
    action must therefore say so in terms they can act on -- and until they
    redeploy, the rules behind it report UNKNOWN rather than PASS.
    """

    def test_the_current_role_is_v5(self) -> None:
        assert rbac.ROLE_VERSION == "v5"
        assert rbac.role_is_current("v5")

    def test_a_v4_role_lacks_exactly_the_defender_read(self) -> None:
        assert rbac.actions_missing_from("v4") == (
            "Microsoft.Security/assessments/read",
        )
        assert rbac.categories_behind("v4") == frozenset({EvidenceCategory.POSTURE})

    def test_a_v3_role_lacks_the_auditing_and_defender_reads(self) -> None:
        assert set(rbac.actions_missing_from("v3")) == {
            "Microsoft.Sql/servers/auditingSettings/read",
            "Microsoft.Security/assessments/read",
        }
        assert not rbac.role_is_current("v3")

    def test_a_v3_role_loses_the_database_and_posture_categories(self) -> None:
        """Every other category keeps working. If this returned more, an upgrade
        would be costing a customer checks the new actions have nothing to do
        with."""
        assert rbac.categories_behind("v3") == frozenset(
            {EvidenceCategory.DATABASE, EvidenceCategory.POSTURE}
        )

    def test_a_v2_role_is_behind_on_vaults_and_databases(self) -> None:
        assert rbac.categories_behind("v2") == frozenset(
            {
                EvidenceCategory.SECRETS,
                EvidenceCategory.DATABASE,
                EvidenceCategory.POSTURE,
            }
        )

    def test_v1_still_reports_every_gap_it_has(self) -> None:
        """v2 added Resource Graph, v3 vaults, v4 SQL auditing. A history that
        quietly forgot an older gap would tell a v1 customer they were one
        action away when they are several."""
        assert rbac.categories_behind("v1") == frozenset(
            {
                EvidenceCategory.RESOURCES,
                EvidenceCategory.SECRETS,
                EvidenceCategory.DATABASE,
                EvidenceCategory.POSTURE,
            }
        )

    def test_every_shipped_version_is_a_prefix_of_the_next(self) -> None:
        """A version may add actions and may never drop one. Removing an action
        from a published set would silently narrow what a deployed role is
        believed to grant, and ``actions_missing_from`` would stop reporting a
        gap that is still real.
        """
        versions = ["v1", "v2", "v3", "v4", "v5"]
        for older, newer in itertools.pairwise(versions):
            assert set(rbac.ROLE_HISTORY[older]) <= set(rbac.ROLE_HISTORY[newer]), (
                f"{newer} dropped an action {older} granted"
            )

    def test_the_role_asks_for_no_data_plane_permission(self) -> None:
        """The strongest claim this product makes. CloudGuard can report that a
        vault is destroyable or a database unaudited, and cannot read one secret
        or one row -- so no action may reach past the resource's own settings.
        """
        assert [
            a for a in rbac.ARM_READ_ACTIONS if a.startswith("Microsoft.KeyVault/")
        ] == ["Microsoft.KeyVault/vaults/read"]
        assert not [
            a for a in rbac.ARM_READ_ACTIONS if a.endswith("/secrets/read")
        ]
        # Defender is read and never driven. No action here starts a scan,
        # dismisses a finding, or changes what the customer is assessed on.
        assert [
            a for a in rbac.ARM_READ_ACTIONS if a.startswith("Microsoft.Security/")
        ] == ["Microsoft.Security/assessments/read"]

    def test_every_granted_action_is_reached_by_a_collector_call(self) -> None:
        """Already asserted for the role as a whole; restated here because a new
        action is exactly when it stops being true, and an unused permission on
        a consent screen is one a customer is right to refuse."""
        assert rbac.ROLE_ONLY_ACTIONS == ()


# ------------------------------------------------- what the screen is handed
class TestTheConnectionPayloadExplainsTheGap:
    """A boolean can only produce "something is out of date".

    ``role_upgrade_available`` has been on the payload since role versions
    existed and was never read by the frontend, so a customer whose database
    and key vault checks were all reporting UNKNOWN had an access panel telling
    them their role was verified. Fixing the panel needed two more facts: what
    to redeploy toward, and which checks are affected -- because "some checks
    are degraded" is a notification and "databases and key vaults" is a
    decision.
    """

    @staticmethod
    def _payload(role_version: str) -> dict:
        connection = CloudConnection(
            provider=Provider.AZURE,
            name="tenant",
            scope_type=ConnectionScope.TENANT_ROOT,
            role_version=role_version,
            consent_status=ConsentStatus.GRANTED,
            status=CloudAccountStatus.ACTIVE,
        )
        connection.id = uuid.uuid4()
        connection.tenant_id = "8e482025-7ac9-4323-81e5-bc9fa528afd7"
        connection.rbac_verified_at = datetime.now(UTC)
        connection.created_at = datetime.now(UTC)
        return routes._serialize(connection)

    def test_a_current_role_reports_no_gap(self) -> None:
        payload = self._payload(rbac.ROLE_VERSION)

        assert payload["role_upgrade_available"] is False
        assert payload["degraded_categories"] == []

    def test_a_stale_role_names_the_version_to_redeploy_toward(self) -> None:
        payload = self._payload("v3")

        assert payload["role_upgrade_available"] is True
        assert payload["role_required_version"] == rbac.ROLE_VERSION

    def test_the_required_version_is_asked_of_the_service_not_the_connector(
        self,
    ) -> None:
        """The route layer is provider-neutral and a role version is not.

        A first attempt imported ``rbac.ROLE_VERSION`` straight into the route,
        which the provider-seam test rejected: the day a second connector lands,
        "the version to redeploy toward" is that provider's answer rather than
        Azure's constant.
        """
        from app.services import cloud_connections as service

        azure = CloudConnection(
            provider=Provider.AZURE,
            name="azure",
            scope_type=ConnectionScope.TENANT_ROOT,
            role_version="v3",
        )
        assert service.required_role_version(azure) == rbac.ROLE_VERSION

    def test_a_stale_role_names_the_checks_that_cannot_run(self) -> None:
        """The same categories the scanner uses to explain its own gaps, so the
        screen and the scan cannot disagree about which checks are affected."""
        assert self._payload("v4")["degraded_categories"] == ["posture"]
        assert self._payload("v3")["degraded_categories"] == ["database", "posture"]
        assert self._payload("v2")["degraded_categories"] == [
            "database",
            "posture",
            "secrets",
        ]

