"""What CloudGuard needs Azure RBAC to allow, and the ARM template that grants it.

The list below is not aspirational. Every action corresponds to a read
operation CloudGuard performs during a scan. The custom role contains exactly
these actions and nothing else -- no ``*/action`` entries, no ``listKeys``,
no data plane, nothing that could read the contents of a customer's storage
or database. The claim "CloudGuard cannot perform a single write in your
environment" is checkable from this file.

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
