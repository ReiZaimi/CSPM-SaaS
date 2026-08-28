"""What CloudGuard needs Azure RBAC to allow, and the ARM template that grants it.

Every action here is ``*/read``. The custom role contains these and nothing
else -- no ``*/action`` entries, no ``listKeys``, no data plane, nothing that
could read the contents of a customer's storage or database. The claim
"CloudGuard cannot perform a single write in your environment" is checkable
from this file, and a test enforces it.

**Every action here is reached by a real collector call, and nothing else is.**
The role was briefly wider, carrying permissions declared ahead of the rules
that would use them. That is no longer the trade being made, for a reason worth
recording: ARM validates a role definition atomically, so a single string that
is not a genuine provider operation fails the entire deployment with
``InvalidActionOrNotAction`` -- and the customer sees "Deployment Failed", not a
note about one permission. ``Microsoft.Security/autoProvisioningSettings/read``
looked exactly as plausible as its neighbours and was not real.

An action a collector call exercises is proven correct the first time that call
succeeds. An action nothing calls has never been checked against Azure by
anything. So the list is now exactly the former, and both directions are
enforced by tests: every call has an action, and every action has a call.

Adding a permission ahead of its rule is still reasonable, but not on trust --
verify the string first with
``az provider operation show --namespace <Namespace>``.

Bump ``ROLE_VERSION`` when the action list changes, so a deployed role that
predates a new rule can be identified and the customer offered a redeploy
rather than silently collecting UNKNOWN results.
"""

import json
from dataclasses import dataclass

from app.core.enums import ConnectionScope

# Bump when the action list changes.
ROLE_VERSION = "v1"

ROLE_NAME = "CloudGuard Security Scanner"

# ARM read actions required for MVP scanning. Organized by resource category.
# Every action here is ``*/read`` -- no writes, no data actions.
ARM_READ_ACTIONS: tuple[str, ...] = (
    # Subscriptions & resources
    "Microsoft.Resources/subscriptions/read",
    "Microsoft.Resources/subscriptions/resources/read",
    # Networking
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Network/networkInterfaces/read",
    "Microsoft.Network/publicIPAddresses/read",
    # Compute
    "Microsoft.Compute/virtualMachines/read",
    # Storage
    "Microsoft.Storage/storageAccounts/read",
    # SQL
    "Microsoft.Sql/servers/read",
    "Microsoft.Sql/servers/firewallRules/read",
    # PostgreSQL -- flexible servers only; single-server is not collected.
    "Microsoft.DBforPostgreSQL/flexibleServers/read",
    # Monitoring & diagnostics
    "Microsoft.Insights/diagnosticSettings/read",
    # Authorization -- who already has access, and under which definitions
    "Microsoft.Authorization/roleAssignments/read",
    "Microsoft.Authorization/roleDefinitions/read",
)

# Which ARM action each collector call needs. This is the link between the code
# and the permission set, and it is what the forward guard checks: add a call to
# ArmClient without adding it here and the test fails, rather than a customer
# discovering it as a 403 buried in one collection category.
#
# Keys are method names on app.connectors.azure.client.ArmClient.
CLIENT_ACTIONS: dict[str, tuple[str, ...]] = {
    "list_subscriptions": ("Microsoft.Resources/subscriptions/read",),
    "list_resources": ("Microsoft.Resources/subscriptions/resources/read",),
    "list_network_security_groups": ("Microsoft.Network/networkSecurityGroups/read",),
    "list_network_interfaces": ("Microsoft.Network/networkInterfaces/read",),
    "list_public_ips": ("Microsoft.Network/publicIPAddresses/read",),
    "list_virtual_machines": ("Microsoft.Compute/virtualMachines/read",),
    "list_storage_accounts": ("Microsoft.Storage/storageAccounts/read",),
    "list_sql_servers": ("Microsoft.Sql/servers/read",),
    "list_sql_firewall_rules": ("Microsoft.Sql/servers/firewallRules/read",),
    "list_postgresql_servers": ("Microsoft.DBforPostgreSQL/flexibleServers/read",),
    "list_diagnostic_settings": ("Microsoft.Insights/diagnosticSettings/read",),
    "list_role_assignments": ("Microsoft.Authorization/roleAssignments/read",),
    "list_role_assignments_at_scope": ("Microsoft.Authorization/roleAssignments/read",),
    "list_role_definitions": ("Microsoft.Authorization/roleDefinitions/read",),
}

# Which collection category each ARM action serves, for the categories the
# collector actually gathers. Identity is Graph-only and has no ARM action;
# the two Authorization reads serve connection verification rather than a
# collection category, so neither appears here.
#
# This exists so a 403 can be explained rather than merely reported. When a
# customer's deployed role predates a check, the resulting failure is not
# "Forbidden" -- it is "redeploy the role", which is a thing they can act on.
COLLECTION_ACTIONS: dict[str, tuple[str, ...]] = {
    "resources": (
        "Microsoft.Resources/subscriptions/read",
        "Microsoft.Resources/subscriptions/resources/read",
    ),
    "network": (
        "Microsoft.Network/networkSecurityGroups/read",
        "Microsoft.Network/networkInterfaces/read",
        "Microsoft.Network/publicIPAddresses/read",
    ),
    "compute": ("Microsoft.Compute/virtualMachines/read",),
    "storage": ("Microsoft.Storage/storageAccounts/read",),
    "database": (
        "Microsoft.Sql/servers/read",
        "Microsoft.Sql/servers/firewallRules/read",
        "Microsoft.DBforPostgreSQL/flexibleServers/read",
    ),
    "logging": ("Microsoft.Insights/diagnosticSettings/read",),
}

# What each published role version granted. Frozen once shipped: a customer's
# deployed role is whatever it was on the day they deployed it, and the only
# way to know which checks their role cannot serve is to have kept the record.
#
# Bumping ROLE_VERSION means adding an entry here, never editing an old one.
#
# Every version is written out literally, and that repetition is the point.
# Writing ``"v1": ARM_READ_ACTIONS`` reads as the same thing and is not: it
# binds the *name*, so the next person to append an action for v2 would silently
# redefine what v1 granted as well. v1 and v2 would then hold identical action
# sets, ``actions_missing_from("v1")`` would return nothing, and no customer
# would ever be told to redeploy -- the exact silence this module exists to
# break, reintroduced by an edit that looks like housekeeping.
ROLE_HISTORY: dict[str, tuple[str, ...]] = {
    "v1": (
        "Microsoft.Resources/subscriptions/read",
        "Microsoft.Resources/subscriptions/resources/read",
        "Microsoft.Network/networkSecurityGroups/read",
        "Microsoft.Network/networkInterfaces/read",
        "Microsoft.Network/publicIPAddresses/read",
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Sql/servers/read",
        "Microsoft.Sql/servers/firewallRules/read",
        "Microsoft.DBforPostgreSQL/flexibleServers/read",
        "Microsoft.Insights/diagnosticSettings/read",
        "Microsoft.Authorization/roleAssignments/read",
        "Microsoft.Authorization/roleDefinitions/read",
    ),
}


def actions_missing_from(role_version: str) -> tuple[str, ...]:
    """Actions the current role requires that ``role_version`` never granted.

    An unrecognised version is treated as granting nothing. That is the safe
    direction: a role CloudGuard has no record of is one whose contents it
    cannot vouch for, and over-reporting a gap costs a redeploy prompt while
    under-reporting one costs silent UNKNOWNs.
    """
    granted = frozenset(ROLE_HISTORY.get(role_version, ()))
    return tuple(a for a in ARM_READ_ACTIONS if a not in granted)


def categories_behind(role_version: str) -> frozenset[str]:
    """Collection categories ``role_version`` cannot fully serve."""
    missing = frozenset(actions_missing_from(role_version))
    if not missing:
        return frozenset()
    return frozenset(
        category
        for category, actions in COLLECTION_ACTIONS.items()
        if missing.intersection(actions)
    )


def role_is_current(role_version: str) -> bool:
    return not actions_missing_from(role_version)


# Anything granted that no collector call reaches. Expected to be empty: the
# role is trimmed to what the scanner proves it needs. Derived rather than
# hand-listed so it cannot disagree with the two definitions above, and
# asserted empty by the tests -- a non-empty value means a permission is being
# requested on a customer's consent screen that nothing has ever used.
ROLE_ONLY_ACTIONS: tuple[str, ...] = tuple(
    action
    for action in ARM_READ_ACTIONS
    if action not in {a for actions in CLIENT_ACTIONS.values() for a in actions}
)



@dataclass(frozen=True)
class TemplateContext:
    """Everything the ARM template needs, all known after consent.

    ``principal_id`` is the service principal's object id in the customer's
    tenant, read back from Graph after consent.
    """

    principal_id: str
    scope_path: str
    scope_type: ConnectionScope
    role_version: str = ROLE_VERSION
    display_name: str = ROLE_NAME

    @property
    def role_full_name(self) -> str:
        return f"{self.display_name} ({self.role_version})"


def role_definition(context: TemplateContext) -> dict:
    """The custom role, in the shape ARM expects."""
    return {
        "Name": context.role_full_name,
        "IsCustom": True,
        "Description": (
            f"Read-only access for CloudGuard cloud security posture scanning. "
            f"Grants {len(ARM_READ_ACTIONS)} read operations and no actions."
        ),
        "Actions": list(ARM_READ_ACTIONS),
        "NotActions": [],
        "DataActions": [],
        "NotDataActions": [],
        "AssignableScopes": [context.scope_path],
    }


def arm_template(context: TemplateContext) -> str:
    """A complete ARM template that creates the custom role and assigns it.

    This is what the "Deploy to Azure" button delivers. Azure Portal fetches
    the template JSON, shows the customer a review screen, and they click
    Create. The template is pre-filled -- no parameters to type.

    Role assignment names use ``[guid()]`` over scope + principal for
    idempotency: a redeployment is a no-op, not an error.
    """
    scope_kind = (
        "subscription"
        if context.scope_type == ConnectionScope.SUBSCRIPTION
        else "managementGroup"
    )
    target = (
        "subscription()"
        if context.scope_type == ConnectionScope.SUBSCRIPTION
        else "managementGroup()"
    )

    actions = [{
        "actions": list(ARM_READ_ACTIONS),
        "notActions": [],
        "dataActions": [],
        "notDataActions": [],
    }]

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-08-01/managementGroupDeploymentTemplate.json#"
        if scope_kind == "managementGroup"
        else "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "description": (
                f"Grants CloudGuard read-only access ({len(ARM_READ_ACTIONS)} "
                f"specific read operations, no writes) for cloud security posture scanning."
            ),
        },
        "variables": {
            "principalId": context.principal_id,
            "roleName": context.role_full_name,
            "roleDescription": (
                f"Read-only access for CloudGuard cloud security posture scanning. "
                f"Grants {len(ARM_READ_ACTIONS)} read operations and no actions."
            ),
        },
        "resources": [
            {
                "type": "Microsoft.Authorization/roleDefinitions",
                "apiVersion": "2022-04-01",
                "name": f"[guid({target}.id, 'cloudguard-scanner', '{context.role_version}')]",
                "properties": {
                    "roleName": "[variables('roleName')]",
                    "description": "[variables('roleDescription')]",
                    "type": "CustomRole",
                    "permissions": actions,
                    "assignableScopes": [f"[{target}.id]"],
                },
            },
            {
                "type": "Microsoft.Authorization/roleAssignments",
                "apiVersion": "2022-04-01",
                "name": f"[guid({target}.id, variables('principalId'), "
                f"resourceId('Microsoft.Authorization/roleDefinitions', "
                f"guid({target}.id, 'cloudguard-scanner', '{context.role_version}')))]",
                "dependsOn": [
                    f"[resourceId('Microsoft.Authorization/roleDefinitions', "
                    f"guid({target}.id, 'cloudguard-scanner', '{context.role_version}'))]"
                ],
                "properties": {
                    "roleDefinitionId": f"[resourceId('Microsoft.Authorization/roleDefinitions', "
                    f"guid({target}.id, 'cloudguard-scanner', '{context.role_version}'))]",
                    "principalId": "[variables('principalId')]",
                    "principalType": "ServicePrincipal",
                },
            },
        ],
    }

    return json.dumps(template, indent=2)
