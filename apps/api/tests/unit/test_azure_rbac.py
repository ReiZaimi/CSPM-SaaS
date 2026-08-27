"""The least-privilege role, and the artifacts that grant it.

The first test is the one that matters. A custom role is only least-privilege
if it is *complete* -- an ARM call with no matching action fails in production
against a customer who chose the narrow role, and it fails as a 403 buried in
one collection category, which surfaces as UNKNOWN rather than as an error
anybody reads. The reverse direction matters too: an action with no call is a
permission CloudGuard asks for and never uses, which is exactly what a security
reviewer looks for on the consent screen.
"""

import inspect

from app.connectors.azure.client import ArmClient
from app.connectors.azure.rbac import (
    ARM_READ_ACTIONS,
    CLIENT_ACTIONS,
    ArtifactContext,
    bicep_template,
    cli_script,
    role_definition,
    terraform_module,
)
from app.core.enums import ConnectionScope, PermissionMode


def context(
    scope_type: ConnectionScope = ConnectionScope.SUBSCRIPTION,
    permission_mode: PermissionMode = PermissionMode.CUSTOM_ROLE,
) -> ArtifactContext:
    scope_path = (
        "/subscriptions/00000000-0000-0000-0000-000000000001"
        if scope_type == ConnectionScope.SUBSCRIPTION
        else "/providers/Microsoft.Management/managementGroups/contoso"
    )
    return ArtifactContext(
        principal_id="99999999-8888-7777-6666-555555555555",
        scope_path=scope_path,
        scope_type=scope_type,
        permission_mode=permission_mode,
        external_id="deadbeefdeadbeef",
    )


def arm_client_calls() -> set[str]:
    """Every ARM request method, read off the class rather than a list."""
    return {
        name
        for name, member in vars(ArmClient).items()
        if not name.startswith("_") and inspect.iscoroutinefunction(member)
    }


# --- the role is complete, and no larger than it needs to be ---------------


def test_every_arm_call_has_a_matching_action() -> None:
    """Add a call to ArmClient without an action and a custom-role customer
    silently loses that whole collection category to a 403."""
    missing = sorted(arm_client_calls() - set(CLIENT_ACTIONS))
    assert missing == [], f"ArmClient methods with no RBAC action: {missing}"


def test_no_action_is_declared_for_a_call_that_does_not_exist() -> None:
    """The other direction: a permission requested and never used."""
    stale = sorted(set(CLIENT_ACTIONS) - arm_client_calls())
    assert stale == [], f"Actions mapped to methods that no longer exist: {stale}"


def test_the_role_grants_reads_only() -> None:
    """The whole claim, in one assertion. No */action, so no listKeys, no data
    plane, and nothing that could modify a customer's environment."""
    assert ARM_READ_ACTIONS
    for action in ARM_READ_ACTIONS:
        assert action.endswith("/read"), action


def test_the_role_is_far_narrower_than_reader() -> None:
    """Reader is `*/read`. This is a countable list, and a short one."""
    assert len(ARM_READ_ACTIONS) < 30
    assert "*/read" not in ARM_READ_ACTIONS
    assert "*" not in ARM_READ_ACTIONS


def test_role_definition_has_no_write_surface() -> None:
    definition = role_definition(context())
    assert definition["NotActions"] == []
    assert definition["DataActions"] == []
    assert definition["IsCustom"] is True
    assert definition["AssignableScopes"] == [context().scope_path]


# --- artifacts -------------------------------------------------------------


def test_cli_script_fills_in_every_parameter() -> None:
    """The point of generating per connection: nothing left to transcribe."""
    script = cli_script(context())
    assert "99999999-8888-7777-6666-555555555555" in script
    assert "/subscriptions/00000000-0000-0000-0000-000000000001" in script
    assert "deadbeefdeadbeef" in script
    # No unsubstituted placeholders.
    assert "<" not in script.replace("<<'JSON'", "").replace("<<-", "")


def test_reader_script_does_not_create_a_role() -> None:
    script = cli_script(context(permission_mode=PermissionMode.READER))
    assert "--role Reader" in script
    assert "az role definition create" not in script


def test_custom_role_script_creates_then_assigns() -> None:
    script = cli_script(context())
    assert "az role definition create" in script
    assert "az role assignment create" in script
    for action in ARM_READ_ACTIONS:
        assert action in script


def test_bicep_targets_the_right_scope() -> None:
    assert "targetScope = 'subscription'" in bicep_template(context())
    assert "targetScope = 'managementGroup'" in bicep_template(
        context(ConnectionScope.TENANT_ROOT)
    )


def test_bicep_names_assignments_deterministically() -> None:
    """A non-deterministic name makes redeployment an error instead of a no-op."""
    template = bicep_template(context())
    assert "guid(" in template
    assert "principalType: 'ServicePrincipal'" in template


def test_terraform_module_pins_a_provider() -> None:
    module = terraform_module(context())
    assert "hashicorp/azurerm" in module
    assert "azurerm_role_definition" in module
    assert "azurerm_role_assignment" in module


def test_every_format_carries_the_external_id() -> None:
    """It is read back during validation, so an artifact without it evidences
    nothing about who controls the scope."""
    ctx = context()
    for render in (cli_script, bicep_template, terraform_module):
        assert ctx.external_id in render(ctx)
