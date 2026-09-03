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
from typing import ClassVar

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



# ------------------------------------------------ what the customer deployed
class TestReadingTheGrantedActions:
    """Identifying a deployed role by what it allows, not by its name.

    The version stamped on a connection records which role the customer was
    *offered* on the day they connected. Only Azure knows which one they have,
    and the answer has to come from the actions on the definitions their
    assignments point at -- a role edited in the portal, or the built-in Reader
    assigned instead of the template, both have names that say nothing.
    """

    @staticmethod
    def _permissions(*actions: str, denied: tuple[str, ...] = ()) -> list[dict]:
        return [{"actions": list(actions), "notActions": list(denied)}]

    def test_the_current_role_reads_back_as_current(self) -> None:
        granted = rbac.actions_granted_by(self._permissions(*ARM_READ_ACTIONS))

        assert granted == frozenset(ARM_READ_ACTIONS)
        assert rbac.version_of_granted(granted) == ROLE_VERSION

    def test_an_older_role_reads_back_as_the_version_it_is(self) -> None:
        granted = rbac.actions_granted_by(self._permissions(*ROLE_HISTORY["v3"]))

        assert rbac.version_of_granted(granted) == "v3"

    def test_the_built_in_reader_is_not_behind(self) -> None:
        """``*/read`` grants a superset of v5. A customer who assigned Reader
        rather than deploying the template has every action this scanner needs,
        and sending them to redeploy would be sending them to fix nothing."""
        granted = rbac.actions_granted_by(self._permissions("*/read"))

        assert granted == frozenset(ARM_READ_ACTIONS)
        assert rbac.version_of_granted(granted) == ROLE_VERSION

    def test_a_notaction_takes_the_version_back_down(self) -> None:
        """An Owner-with-exclusions role really does not grant the excluded
        read, so a role built that way is behind in exactly that category."""
        granted = rbac.actions_granted_by(
            self._permissions("*", denied=("Microsoft.Security/assessments/read",))
        )

        assert "Microsoft.Security/assessments/read" not in granted
        assert rbac.version_of_granted(granted) == "v4"

    def test_a_role_that_was_never_cloudguards_reads_back_as_nothing(self) -> None:
        """None rather than a version string. "I could not tell" is not "v1":
        recording a guess is the lie this whole mechanism exists to stop."""
        granted = rbac.actions_granted_by(
            self._permissions("Microsoft.Web/sites/read")
        )

        assert granted == frozenset()
        assert rbac.version_of_granted(granted) is None

    def test_assignments_combine(self) -> None:
        """Two assignments grant the union. A customer left on v2 who was also
        given Reader is not missing anything."""
        granted = rbac.actions_granted_by(
            [
                *self._permissions(*ROLE_HISTORY["v2"]),
                *self._permissions("*/read"),
            ]
        )

        assert rbac.version_of_granted(granted) == ROLE_VERSION


class FakeArm:
    """An ArmClient that answers from a prepared tenant."""

    assignments: ClassVar[list[dict]] = []
    definitions: ClassVar[dict[str, list[dict]]] = {}
    fails: bool = False
    scopes_read: ClassVar[list[str]] = []

    def __init__(self, tokens: object) -> None:
        pass

    async def __aenter__(self) -> "FakeArm":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def list_role_assignments_at_scope(self, scope: str) -> list[dict]:
        if type(self).fails:
            raise RuntimeError("403")
        type(self).scopes_read.append(scope)
        return type(self).assignments

    async def get_role_definition(self, definition_id: str) -> dict:
        return {
            "properties": {"permissions": type(self).definitions.get(definition_id, [])}
        }


class FakeSession:
    """Enough of an AsyncSession for a service call that only commits."""

    def __init__(self) -> None:
        self.info: dict = {}
        self.commits = 0

    async def commit(self) -> None:
        self.commits += 1


class TestTheDeployedRoleIsRecorded:
    """The bug a customer reported: redeploying changed nothing on screen.

    The role was assigned in Azure, the checks it enables started working, and
    the access panel went on saying "v2, behind (v5)" with the banner up --
    because nothing had read ``role_version`` back since the row was created.
    """

    PRINCIPAL = "9a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"

    @pytest.fixture(autouse=True)
    def azure(self, monkeypatch: pytest.MonkeyPatch):
        from app.connectors.azure import auth

        class FakeTokens:
            def __init__(self, tenant_id: str) -> None:
                self.tenant_id = tenant_id

        monkeypatch.setattr(auth, "TokenProvider", FakeTokens)
        monkeypatch.setattr("app.services.cloud_connections.ArmClient", FakeArm)
        FakeArm.assignments = []
        FakeArm.definitions = {}
        FakeArm.fails = False
        FakeArm.scopes_read = []
        return FakeArm

    def _connection(self, role_version: str = "v2") -> CloudConnection:
        connection = make_connection(role_version)
        connection.id = uuid.uuid4()
        connection.tenant_id = "8e482025-7ac9-4323-81e5-bc9fa528afd7"
        connection.service_principal_object_id = self.PRINCIPAL
        connection.rbac_verified_at = datetime.now(UTC)
        return connection

    def _deploy(self, actions: tuple[str, ...], principal: str | None = None) -> None:
        FakeArm.assignments = [
            {
                "properties": {
                    "principalId": principal or self.PRINCIPAL,
                    "roleDefinitionId": "/providers/.../roleDefinitions/role-1",
                }
            }
        ]
        FakeArm.definitions = {
            "/providers/.../roleDefinitions/role-1": [
                {"actions": list(actions), "notActions": []}
            ]
        }

    async def test_a_redeployed_role_clears_the_banner(self) -> None:
        from app.services import cloud_connections as service

        connection = self._connection("v2")
        self._deploy(ARM_READ_ACTIONS)
        session = FakeSession()

        assert await service.refresh_role_version(session, connection) == ROLE_VERSION
        assert connection.role_version == ROLE_VERSION
        assert role_upgrade_available(connection) is False
        assert degraded_categories(connection) == {}
        assert session.commits == 1

    async def test_the_scope_asked_about_is_the_connection_s_own(self) -> None:
        """A tenant-root connection's grant lives at the root management group,
        and there is no subscription to ask about."""
        from app.services import cloud_connections as service

        connection = self._connection("v2")
        self._deploy(ARM_READ_ACTIONS)

        await service.refresh_role_version(FakeSession(), connection)

        assert FakeArm.scopes_read == [connection.scope_path]

    async def test_an_unchanged_role_is_not_rewritten(self) -> None:
        from app.services import cloud_connections as service

        connection = self._connection(ROLE_VERSION)
        self._deploy(ARM_READ_ACTIONS)
        session = FakeSession()

        assert await service.refresh_role_version(session, connection) is None
        assert session.commits == 0

    async def test_a_failed_probe_leaves_the_recorded_version_alone(self) -> None:
        """The safe direction. A refused call is not evidence the role changed,
        and overwriting a known version with a guess would put the customer on
        a redeploy they may not need -- or worse, take the prompt away."""
        from app.services import cloud_connections as service

        connection = self._connection("v2")
        FakeArm.fails = True

        assert await service.detect_role_version(connection) is None
        assert await service.refresh_role_version(FakeSession(), connection) is None
        assert connection.role_version == "v2"

    async def test_assignments_to_other_principals_are_not_cloudguard_s(self) -> None:
        """Every assignment at a subscription is listed, most of them the
        customer's own people. Reading somebody else's Owner grant as
        CloudGuard's role would report v5 for a connection with no access."""
        from app.services import cloud_connections as service

        connection = self._connection("v2")
        self._deploy(ARM_READ_ACTIONS, principal="00000000-0000-0000-0000-00000000beef")

        assert await service.detect_role_version(connection) is None
        assert connection.role_version == "v2"

    async def test_a_role_deployed_at_the_old_version_still_reads_current(self) -> None:
        """Why the template stopped being stamped with the stored version.

        The redeploy link rendered a template named for whatever version the row
        held, so the deployment updated the *old* role definition in place with
        today's actions. The name stayed "(v2)" and the actions were v5's --
        which is exactly why identification reads actions and not names.
        """
        from app.services import cloud_connections as service

        connection = self._connection("v2")
        self._deploy(ARM_READ_ACTIONS)

        assert await service.detect_role_version(connection) == ROLE_VERSION


def test_the_redeploy_template_grants_the_current_role() -> None:
    """What "Redeploy the role" has to deliver. Rendered from the stored
    version, the template created its role definition under the old version's
    name and deterministic guid, so redeploying could not produce the role the
    screen was asking for."""
    import json

    from app.services.cloud_connections import render_template

    connection = make_connection("v2")
    connection.id = uuid.uuid4()
    connection.tenant_id = "8e482025-7ac9-4323-81e5-bc9fa528afd7"
    connection.service_principal_object_id = "9a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"

    template = json.loads(render_template(connection))
    definition = template["resources"][0]

    assert f"'{ROLE_VERSION}'" in definition["name"]
    assert "'v2'" not in definition["name"]
    assert template["variables"]["roleName"].endswith(f"({ROLE_VERSION})")
