"""What CloudGuard needs Azure RBAC to allow, and the artifacts that grant it.

The list below is not aspirational. Every action corresponds to exactly one
method on :class:`app.connectors.azure.client.ArmClient`, and a test asserts the
correspondence in both directions -- an ARM call with no action would fail
against a custom role in production, and an action with no call would be a
permission CloudGuard asks for and never uses. Both are least-privilege
failures; the second is the kind a customer's security reviewer notices.

Set against Azure's built-in ``Reader`` (``*/read``, thousands of operations
across every resource provider), this is thirteen. Note also what is absent:
there are no ``*/action`` entries at all. No ``listKeys``, no data plane,
nothing that could read the contents of a customer's storage or database. The
claim "CloudGuard cannot perform a single write in your environment" is
checkable from this file.

The trade is maintenance. A rule that reads a new resource type needs a new
action here, and every customer on a custom role has to redeploy -- which is why
``role_version`` exists and why Reader remains the default offer.
"""

from dataclasses import dataclass

from app.core.enums import ConnectionScope, PermissionMode

# Bump when the action list changes, so a deployed role that predates a new rule
# can be identified and the customer offered a redeploy rather than silently
# collecting UNKNOWN results.
ROLE_VERSION = "v1"

ROLE_NAME = "CloudGuard Security Scanner"

# ArmClient method -> the ARM action it needs. The mapping is the source of
# truth; ARM_READ_ACTIONS below is derived from it, so the two cannot drift.
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
    # Only flexible servers are collected today; single-server deployments are
    # not read at all, so the role does not ask for them.
    "list_postgresql_servers": ("Microsoft.DBforPostgreSQL/flexibleServers/read",),
    "list_diagnostic_settings": ("Microsoft.Insights/diagnosticSettings/read",),
    "list_role_assignments": ("Microsoft.Authorization/roleAssignments/read",),
    "list_role_assignments_at_scope": ("Microsoft.Authorization/roleAssignments/read",),
    "list_role_definitions": ("Microsoft.Authorization/roleDefinitions/read",),
}

ARM_READ_ACTIONS: tuple[str, ...] = tuple(
    dict.fromkeys(action for actions in CLIENT_ACTIONS.values() for action in actions)
)


@dataclass(frozen=True)
class ArtifactContext:
    """Everything an artifact needs, all of it known before the customer acts.

    ``principal_id`` is the service principal's object id in the customer's own
    tenant, read back from Graph after consent. Having it is what turns this
    step from "find CloudGuard in the portal and assign it a role" into a
    command with nothing left to fill in.
    """

    principal_id: str
    scope_path: str
    scope_type: ConnectionScope
    permission_mode: PermissionMode
    external_id: str
    role_version: str = ROLE_VERSION
    display_name: str = ROLE_NAME

    @property
    def role_full_name(self) -> str:
        return f"{self.display_name} ({self.role_version})"

    @property
    def is_custom(self) -> bool:
        return self.permission_mode == PermissionMode.CUSTOM_ROLE


def role_definition(context: ArtifactContext) -> dict:
    """The custom role, in the shape ``az role definition create`` expects."""
    return {
        "Name": context.role_full_name,
        "IsCustom": True,
        "Description": (
            f"Read-only access for CloudGuard cloud security posture scanning. "
            f"Grants {len(ARM_READ_ACTIONS)} read operations and no actions. "
            f"CloudGuardExternalId={context.external_id}"
        ),
        "Actions": list(ARM_READ_ACTIONS),
        "NotActions": [],
        "DataActions": [],
        "NotDataActions": [],
        "AssignableScopes": [context.scope_path],
    }


def cli_script(context: ArtifactContext) -> str:
    """A single paste into Azure Cloud Shell.

    A shell script rather than an ARM template because ARM cannot reach Entra --
    it deploys resources, and a service principal is not one. The consent step
    has already created the principal; this only has RBAC left to do, which ARM
    *can* express, so a template is offered too (see :func:`bicep_template`).
    What the script buys over the template is that it runs where the customer is
    already authenticated, with no parameters to transcribe.
    """
    header = f"""#!/usr/bin/env bash
# CloudGuard -- grant read-only access
#
# Run this in Azure Cloud Shell, or anywhere `az` is signed in as a user with
# Owner or User Access Administrator on the scope below. Note that this is a
# different permission from the Global Administrator who granted admin consent;
# often a different person.
#
# Scope:      {context.scope_path}
# Principal:  {context.principal_id}  (CloudGuard's service principal in your tenant)
set -euo pipefail

PRINCIPAL_ID="{context.principal_id}"
SCOPE="{context.scope_path}"
"""

    if not context.is_custom:
        return header + f"""
az role assignment create \\
  --assignee-object-id "$PRINCIPAL_ID" \\
  --assignee-principal-type ServicePrincipal \\
  --role Reader \\
  --scope "$SCOPE" \\
  --description "CloudGuardExternalId={context.external_id}"

echo "Done. Return to CloudGuard and the connection will verify itself."
"""

    import json

    definition = json.dumps(role_definition(context), indent=2)
    return header + f"""ROLE_NAME="{context.role_full_name}"

# The exact {len(ARM_READ_ACTIONS)} read operations CloudGuard performs. No write
# actions, no data actions -- inspect the list before running this.
cat > /tmp/cloudguard-role.json <<'JSON'
{definition}
JSON

# Idempotent: update the definition if this scope already has it.
EXISTING=$(az role definition list --name "$ROLE_NAME" --scope "$SCOPE" \
  --query "[0].roleName" -o tsv)
if [ -n "$EXISTING" ]; then
  az role definition update --role-definition /tmp/cloudguard-role.json
else
  az role definition create --role-definition /tmp/cloudguard-role.json
fi

az role assignment create \\
  --assignee-object-id "$PRINCIPAL_ID" \\
  --assignee-principal-type ServicePrincipal \\
  --role "$ROLE_NAME" \\
  --scope "$SCOPE" \\
  --description "CloudGuardExternalId={context.external_id}"

echo "Done. Return to CloudGuard and the connection will verify itself."
"""


def bicep_template(context: ArtifactContext) -> str:
    """The same grant as ARM, for customers whose change process wants one.

    Role assignment names must be deterministic GUIDs or a redeployment errors
    instead of being a no-op, hence ``guid()`` over the scope and principal.
    """
    target = (
        "subscription()"
        if context.scope_type == ConnectionScope.SUBSCRIPTION
        else "managementGroup()"
    )
    scope_kind = (
        "subscription"
        if context.scope_type == ConnectionScope.SUBSCRIPTION
        else "managementGroup"
    )
    description = f"CloudGuardExternalId={context.external_id}"

    if not context.is_custom:
        # acdd72a7-3385-48ef-bd42-f606fba81ae7 is Azure's built-in Reader.
        return f"""targetScope = '{scope_kind}'

@description('CloudGuard service principal object id in this tenant')
param principalId string = '{context.principal_id}'

var readerRoleId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'

resource assignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {{
  name: guid({target}.id, principalId, readerRoleId)
  properties: {{
    roleDefinitionId: tenantResourceId(
      'Microsoft.Authorization/roleDefinitions', readerRoleId
    )
    principalId: principalId
    principalType: 'ServicePrincipal'
    description: '{description}'
  }}
}}
"""

    actions = "\n".join(f"          '{action}'" for action in ARM_READ_ACTIONS)
    return f"""targetScope = '{scope_kind}'

@description('CloudGuard service principal object id in this tenant')
param principalId string = '{context.principal_id}'

@description('Bumped when CloudGuard needs a new read operation')
param roleVersion string = '{context.role_version}'

resource role 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {{
  // Deterministic so redeploying updates the role instead of failing.
  name: guid({target}.id, 'cloudguard-scanner', roleVersion)
  properties: {{
    roleName: '{context.display_name} (${{roleVersion}})'
    description: '{description}'
    type: 'CustomRole'
    permissions: [
      {{
        actions: [
{actions}
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }}
    ]
    assignableScopes: [ {target}.id ]
  }}
}}

resource assignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {{
  name: guid({target}.id, principalId, role.id)
  properties: {{
    roleDefinitionId: role.id
    principalId: principalId
    principalType: 'ServicePrincipal'
    description: '{description}'
  }}
}}
"""


def terraform_module(context: ArtifactContext) -> str:
    """For platform teams who want this reviewed and committed, not pasted."""
    scope_comment = (
        "# Scope is a management group; azurerm resolves it by id."
        if context.scope_type != ConnectionScope.SUBSCRIPTION
        else "# Scope is a single subscription."
    )

    if not context.is_custom:
        return f"""terraform {{
  required_providers {{
    azurerm = {{ source = "hashicorp/azurerm", version = "~> 3.0" }}
  }}
}}

provider "azurerm" {{ features {{}} }}

{scope_comment}
locals {{
  cloudguard_scope        = "{context.scope_path}"
  cloudguard_principal_id = "{context.principal_id}"
}}

resource "azurerm_role_assignment" "cloudguard" {{
  scope                = local.cloudguard_scope
  role_definition_name = "Reader"
  principal_id         = local.cloudguard_principal_id
  principal_type       = "ServicePrincipal"
  description          = "CloudGuardExternalId={context.external_id}"
}}
"""

    actions = "\n".join(f'      "{action}",' for action in ARM_READ_ACTIONS)
    return f"""terraform {{
  required_providers {{
    azurerm = {{ source = "hashicorp/azurerm", version = "~> 3.0" }}
  }}
}}

provider "azurerm" {{ features {{}} }}

{scope_comment}
locals {{
  cloudguard_scope        = "{context.scope_path}"
  cloudguard_principal_id = "{context.principal_id}"
}}

# The exact {len(ARM_READ_ACTIONS)} read operations CloudGuard performs.
resource "azurerm_role_definition" "cloudguard" {{
  name        = "{context.role_full_name}"
  scope       = local.cloudguard_scope
  description = "CloudGuardExternalId={context.external_id}"

  permissions {{
    actions = [
{actions}
    ]
    not_actions = []
  }}

  assignable_scopes = [local.cloudguard_scope]
}}

resource "azurerm_role_assignment" "cloudguard" {{
  scope              = local.cloudguard_scope
  role_definition_id = azurerm_role_definition.cloudguard.role_definition_resource_id
  principal_id       = local.cloudguard_principal_id
  principal_type     = "ServicePrincipal"
  description        = "CloudGuardExternalId={context.external_id}"
}}
"""


ARTIFACT_FORMATS = {
    "cli": ("text/x-shellscript", "cloudguard-connect.sh", cli_script),
    "bicep": ("text/plain", "cloudguard-connect.bicep", bicep_template),
    "terraform": ("text/plain", "cloudguard-connect.tf", terraform_module),
}
