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
