"""The least-privilege role, and the ARM template that grants it.

The first test is the one that matters. A custom role is only least-privilege
if it is *complete* -- an ARM call with no matching action fails in production
as a 403 buried in one collection category, which surfaces as UNKNOWN rather
than as an error anybody reads. The reverse direction matters too: an action
with no call is a permission CloudGuard asks for and never uses, which is
exactly what a security reviewer looks for on the consent screen.
"""

import json

from app.connectors.azure.rbac import (
    ARM_READ_ACTIONS,
    TemplateContext,
    arm_template,
    role_definition,
)
from app.core.enums import ConnectionScope


def context(
    scope_type: ConnectionScope = ConnectionScope.SUBSCRIPTION,
) -> TemplateContext:
    scope_path = (
        "/subscriptions/00000000-0000-0000-0000-000000000001"
        if scope_type == ConnectionScope.SUBSCRIPTION
        else "/providers/Microsoft.Management/managementGroups/contoso"
    )
    return TemplateContext(
        principal_id="99999999-8888-7777-6666-555555555555",
        scope_path=scope_path,
        scope_type=scope_type,
    )


# --- the role is complete, and no larger than it needs to be ---------------


def test_the_role_grants_reads_only() -> None:
    """The whole claim, in one assertion. No */action, so no listKeys, no data
    plane, and nothing that could modify a customer's environment."""
    assert ARM_READ_ACTIONS
    for action in ARM_READ_ACTIONS:
        assert action.endswith("/read"), action


def test_no_wildcard_actions() -> None:
    """The role must not contain any wildcard that would silently expand."""
    assert "*/read" not in ARM_READ_ACTIONS
    assert "*" not in ARM_READ_ACTIONS


def test_role_definition_has_no_write_surface() -> None:
    definition = role_definition(context())
    assert definition["NotActions"] == []
    assert definition["DataActions"] == []
    assert definition["IsCustom"] is True
    assert definition["AssignableScopes"] == [context().scope_path]


# --- ARM template -----------------------------------------------------------


def test_arm_template_is_valid_json() -> None:
    body = arm_template(context())
    parsed = json.loads(body)
    assert parsed["contentVersion"] == "1.0.0.0"


def test_arm_template_contains_role_and_assignment() -> None:
    body = arm_template(context())
    parsed = json.loads(body)
    types = [r["type"] for r in parsed["resources"]]
    assert "Microsoft.Authorization/roleDefinitions" in types
    assert "Microsoft.Authorization/roleAssignments" in types


def test_arm_template_includes_all_actions() -> None:
    body = arm_template(context())
    parsed = json.loads(body)
    role_resource = next(
        r for r in parsed["resources"]
        if r["type"] == "Microsoft.Authorization/roleDefinitions"
    )
    template_actions = role_resource["properties"]["permissions"][0]["actions"]
    assert set(template_actions) == set(ARM_READ_ACTIONS)


def test_arm_template_carries_principal_id() -> None:
    body = arm_template(context())
    assert "99999999-8888-7777-6666-555555555555" in body


def test_arm_template_subscription_schema() -> None:
    body = arm_template(context(ConnectionScope.SUBSCRIPTION))
    parsed = json.loads(body)
    assert "subscriptionDeploymentTemplate" in parsed["$schema"]


def test_arm_template_management_group_schema() -> None:
    body = arm_template(context(ConnectionScope.TENANT_ROOT))
    parsed = json.loads(body)
    assert "managementGroupDeploymentTemplate" in parsed["$schema"]


# --- the forward guard -----------------------------------------------------
#
# Only one direction is enforced. A collector call with no matching action
# fails in production as a 403 inside one collection category, which the engine
# records as UNKNOWN rather than as an error anyone reads -- a scan that looks
# like it worked. The reverse (an action no call reaches) is deliberate here:
# see ROLE_ONLY_ACTIONS.


# Every client that spends ARM permissions. Resource Graph is a separate class
# with its own paging and its own quota, but the permissions it spends are
# still the customer's role, so it is subject to the same guard -- a query the
# role does not grant fails as a 403 in exactly the way an ARM listing would.
ARM_FACING_CLIENTS = ("ArmClient", "ResourceGraphClient")


def _public_calls(client_name: str) -> set[str]:
    import inspect

    from app.connectors.azure import client as client_module

    return {
        name
        for name, member in vars(getattr(client_module, client_name)).items()
        if not name.startswith("_") and inspect.iscoroutinefunction(member)
    }


def arm_client_calls() -> set[str]:
    """Every ARM-permissioned request method, read off the classes."""
    calls: set[str] = set()
    for name in ARM_FACING_CLIENTS:
        calls |= _public_calls(name)
    return calls


def test_the_ledger_can_name_every_call_unambiguously() -> None:
    """CLIENT_ACTIONS is keyed by bare method name, which only works while the
    ARM-facing clients do not share one. Two classes with a ``list_resources``
    apiece would map to a single entry, and the second one's permissions would
    be whatever the first happened to declare."""
    seen: dict[str, str] = {}
    for client_name in ARM_FACING_CLIENTS:
        for method in _public_calls(client_name):
            assert method not in seen, (
                f"{client_name}.{method} collides with {seen[method]}.{method}. "
                "Rename one, or key CLIENT_ACTIONS by class as well."
            )
            seen[method] = client_name


def test_every_arm_call_has_a_matching_action() -> None:
    from app.connectors.azure.rbac import CLIENT_ACTIONS

    missing = sorted(arm_client_calls() - set(CLIENT_ACTIONS))
    assert missing == [], (
        f"ARM-facing client methods with no RBAC action: {missing}. "
        "Add them to CLIENT_ACTIONS and to ARM_READ_ACTIONS, or a custom-role "
        "customer loses that whole collection category to a silent 403."
    )


def test_every_mapped_action_is_actually_granted() -> None:
    """The mapping must not promise a permission the role does not contain."""
    from app.connectors.azure.rbac import ARM_READ_ACTIONS, CLIENT_ACTIONS

    granted = set(ARM_READ_ACTIONS)
    ungranted = sorted(
        {a for actions in CLIENT_ACTIONS.values() for a in actions} - granted
    )
    assert ungranted == [], f"Mapped to actions the role does not grant: {ungranted}"


def test_mapped_methods_all_exist() -> None:
    """Stops the mapping rotting into a list of methods that were renamed."""
    from app.connectors.azure.rbac import CLIENT_ACTIONS

    stale = sorted(set(CLIENT_ACTIONS) - arm_client_calls())
    assert stale == [], f"CLIENT_ACTIONS names methods that no longer exist: {stale}"


def test_no_permission_is_requested_that_nothing_uses() -> None:
    """The reverse guard, reinstated now the role matches the collector.

    Two reasons it earns its place. A permission nothing calls appears on the
    customer's consent screen and cannot be justified when they ask. And it has
    never been checked against Azure by anything: an action a call exercises is
    proven the first time that call succeeds, while an unused one is only ever
    a plausible-looking string. One such string
    (``Microsoft.Security/autoProvisioningSettings/read``) was not real, and
    because ARM validates a role definition atomically it failed the entire
    deployment rather than one permission.
    """
    from app.connectors.azure.rbac import ROLE_ONLY_ACTIONS

    assert ROLE_ONLY_ACTIONS == (), (
        f"Granted but never used: {list(ROLE_ONLY_ACTIONS)}. Add the collector "
        "call that needs it, or drop it from ARM_READ_ACTIONS. If you are "
        "deliberately declaring ahead of a rule, verify the string first with "
        "`az provider operation show --namespace <Namespace>` -- an invalid one "
        "fails the whole ARM deployment, not just that permission."
    )


def test_the_role_is_small_enough_to_read() -> None:
    """Reader is `*/read` across every provider. The point of a custom role is
    that a human can check this list in full."""
    from app.connectors.azure.rbac import ARM_READ_ACTIONS

    assert len(ARM_READ_ACTIONS) <= 20
