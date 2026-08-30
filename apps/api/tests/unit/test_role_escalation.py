"""Which roles can hand out roles, read from the definition rather than the name.

The whole template rests on one distinction, and getting it wrong in either
direction ruins it. **Owner and Contributor both carry ``actions: ["*"]``** --
the only thing separating them is that Contributor excludes
``Microsoft.Authorization/*/Write`` in its ``notActions``. Matching on role
names, or on actions without honouring the exclusions, would report every
Contributor assignment in existence as a privilege escalation path, which is
the kind of false alarm that gets a feature switched off rather than fixed.

The other direction matters too: a tenant's own custom role granting exactly
this one action is invisible to any list of well-known names, and is precisely
the thing worth finding.
"""

from typing import Any

from app.connectors.azure.normalizer import (
    ROLE_ASSIGNMENT_WRITE,
    AzureNormalizer,
    _grants_role_assignment,
)
from app.connectors.base import RawSnapshot
from app.core.enums import Provider, RelationshipType

SUB = "/subscriptions/sub-1"
VM = f"{SUB}/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/jump-01"
PRINCIPAL = "11111111-2222-3333-4444-555555555555"


def role(name: str, actions: list[str], not_actions: list[str] | None = None) -> dict:
    return {
        "id": f"/roleDefinitions/{name}",
        "properties": {
            "roleName": name,
            "permissions": [
                {"actions": actions, "notActions": not_actions or [], "dataActions": []}
            ],
        },
    }


OWNER = role("Owner", ["*"])
CONTRIBUTOR = role(
    "Contributor",
    ["*"],
    [
        "Microsoft.Authorization/*/Delete",
        "Microsoft.Authorization/*/Write",
        "Microsoft.Authorization/elevateAccess/Action",
    ],
)
READER = role("Reader", ["*/read"])
USER_ACCESS_ADMIN = role(
    "User Access Administrator", ["*/read", "Microsoft.Authorization/*"]
)


# ------------------------------------------------------------- the definition
def test_owner_can_grant_roles() -> None:
    assert _grants_role_assignment(OWNER) is True


def test_contributor_cannot() -> None:
    """The case that decides whether this feature is usable at all.

    Contributor holds ``*`` and is excluded from writing role assignments. It is
    on nearly every subscription in existence, and calling it an escalation path
    would bury the real ones.
    """
    assert _grants_role_assignment(CONTRIBUTOR) is False


def test_reader_cannot() -> None:
    assert _grants_role_assignment(READER) is False


def test_user_access_administrator_can() -> None:
    """A narrower wildcard than Owner's, covering exactly this."""
    assert _grants_role_assignment(USER_ACCESS_ADMIN) is True


def test_a_custom_role_naming_the_action_outright_can() -> None:
    """The reason this is read from the definition rather than a name list."""
    custom = role("Deployment Automation", ["Microsoft.Compute/*", ROLE_ASSIGNMENT_WRITE])
    assert _grants_role_assignment(custom) is True


def test_matching_ignores_case() -> None:
    """Azure's own definitions mix ``/Write`` and ``/write`` freely."""
    shouty = role("Shouty", ["MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"])
    assert _grants_role_assignment(shouty) is True


def test_an_exclusion_in_a_later_permission_block_does_not_cancel_an_earlier_grant() -> None:
    """Each permission block stands on its own, which is how ARM evaluates them:
    one block that grants the action without excluding it is enough."""
    mixed = {
        "id": "/roleDefinitions/mixed",
        "properties": {
            "roleName": "Mixed",
            "permissions": [
                {"actions": [ROLE_ASSIGNMENT_WRITE], "notActions": []},
                {"actions": ["*"], "notActions": ["Microsoft.Authorization/*/Write"]},
            ],
        },
    }
    assert _grants_role_assignment(mixed) is True


def test_an_unresolvable_definition_claims_nothing() -> None:
    """An assignment whose definition never came back is a role CloudGuard
    cannot read. Guessing would invent the most consequential edge in the graph
    out of missing data."""
    assert _grants_role_assignment(None) is False
    assert _grants_role_assignment({}) is False


# ------------------------------------------------------------------ the edges
def snapshot(definition: dict) -> RawSnapshot:
    return RawSnapshot(
        provider=Provider.AZURE,
        tenant_id="tenant",
        subscription_id="sub-1",
        data={
            "virtual_machines": [
                {
                    "id": VM,
                    "name": "jump-01",
                    "identity": {"principalId": PRINCIPAL},
                    "properties": {},
                }
            ],
            "role_definitions": [definition],
            "role_assignments": [
                {
                    "id": "/assignment-1",
                    "properties": {
                        "principalId": PRINCIPAL,
                        "principalType": "ServicePrincipal",
                        "scope": SUB,
                        "roleDefinitionId": definition["id"],
                    },
                }
            ],
        },
    )


def edges_for(definition: dict) -> set[RelationshipType]:
    state = AzureNormalizer().normalize(snapshot(definition))
    principal = f"/principals/{PRINCIPAL}"
    return {
        relationship
        for source, relationship, target in state.relationships
        if source == principal and target == SUB
    }


def test_an_escalating_role_draws_both_edges() -> None:
    """Beside, never instead of. They are different claims about the same pair:
    what the principal may do now, and that there is no ceiling on it."""
    assert edges_for(OWNER) == {
        RelationshipType.GRANTS_ROLE,
        RelationshipType.CAN_GRANT_ROLES,
    }


def test_an_ordinary_role_draws_only_the_reach() -> None:
    assert edges_for(CONTRIBUTOR) == {RelationshipType.GRANTS_ROLE}


def test_the_capability_is_recorded_on_the_principal_too() -> None:
    """So a blast-radius view can say why an identity is worth worrying about
    without re-deriving it from the edges."""
    state = AzureNormalizer().normalize(snapshot(OWNER))
    principal = next(
        r for r in state.resources if r.provider_resource_id == f"/principals/{PRINCIPAL}"
    )
    roles: list[dict[str, Any]] = principal.metadata["roles"]

    assert roles[0]["role"] == "Owner"
    assert roles[0]["grants_role_assignment"] is True
