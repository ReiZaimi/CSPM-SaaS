"""What CloudGuard needs Azure RBAC to allow, and the ARM template that grants it.

Every action here is ``*/read``. The custom role contains these and nothing
else -- no ``*/action`` entries, no ``listKeys``, no data plane, nothing that
could read the contents of a customer's storage or database. The claim
"CloudGuard cannot perform a single write in your environment" is checkable
from this file, and a test enforces it.

**The role is deliberately wider than the scanner currently reads.** Some
actions are declared ahead of the rules that will use them, so that a customer
who deploys the role today does not have to redeploy it when those rules ship
-- a role update means going back to whoever holds Owner on the subscription,
which is a far worse tax than a slightly wider read-only grant.
``CLIENT_ACTIONS`` below records which actions the collector reaches today, and
``ROLE_ONLY_ACTIONS`` names the surplus explicitly, so "requested but unused"
is a documented decision rather than something nobody noticed.

The guarantee that *is* enforced runs the other way: every ARM call the
collector makes must have a matching action. A missing one fails in production
as a 403 inside one collection category, which surfaces as UNKNOWN results
rather than as an error anyone reads
(``tests/unit/test_azure_rbac.py::test_every_arm_call_has_a_matching_action``).

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
    "Microsoft.Network/virtualNetworks/read",
    "Microsoft.Network/virtualNetworks/subnets/read",
    # Compute
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/disks/read",
    # Containers
    "Microsoft.ContainerService/managedClusters/read",
    # Storage
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/read",
    # SQL
    "Microsoft.Sql/servers/read",
    "Microsoft.Sql/servers/firewallRules/read",
    "Microsoft.Sql/servers/auditingSettings/read",
    "Microsoft.Sql/servers/databases/transparentDataEncryption/read",
    "Microsoft.Sql/servers/advancedThreatProtectionSettings/read",
    # PostgreSQL
    "Microsoft.DBforPostgreSQL/flexibleServers/read",
    # Key Vault (metadata only -- not secret values)
    "Microsoft.KeyVault/vaults/read",
    # App Services
    "Microsoft.Web/sites/read",
    "Microsoft.Web/sites/config/read",
    # Monitoring & diagnostics
    "Microsoft.Insights/diagnosticSettings/read",
    "Microsoft.OperationalInsights/workspaces/read",
    # Identity & authorization
    "Microsoft.Authorization/roleAssignments/read",
    "Microsoft.Authorization/roleDefinitions/read",
    "Microsoft.Authorization/policyAssignments/read",
    "Microsoft.Authorization/locks/read",
    # Defender for Cloud
    "Microsoft.Security/pricings/read",
    "Microsoft.Security/securityContacts/read",
    "Microsoft.Security/autoProvisioningSettings/read",
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

# Granted but not yet reached by any collector call -- declared ahead of the
# rules that will use them so customers deploy the role once rather than twice.
# Derived, not hand-listed, so it cannot fall out of step with the two above.
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
