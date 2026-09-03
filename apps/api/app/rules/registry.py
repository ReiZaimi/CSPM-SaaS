"""The rule registry — the single source of truth for what CloudGuard checks.

The ``rules`` database table is a read-mirror of this list, synced at startup.
Adding a rule means adding it here and writing its tests; it never means
inserting a database row (RULE_ENGINE.md section 4).
"""

from app.rules.azure.compute.exposure import (
    AzureExposedComputeRule,
    AzureUnguardedVmRule,
)
from app.rules.azure.database.public_access import (
    AzureDatabaseAuditingRule,
    AzureDatabasePrivateConnectivityRule,
    AzurePublicDatabaseRule,
)
from app.rules.azure.identity.credentials import (
    AzureLongLivedApplicationCredentialRule,
)
from app.rules.azure.identity.dormant import AzureDormantPrivilegedAccountRule
from app.rules.azure.identity.mfa import AzureMfaRule
from app.rules.azure.identity.privileged import AzurePrivilegedUserRule
from app.rules.azure.logging.diagnostics import (
    AzureActivityLogExportRule,
    AzureLoggingRule,
)
from app.rules.azure.network.exposure import (
    AzureOpenNsgRule,
    AzurePublicRdpRule,
    AzurePublicSshRule,
    AzurePublicWinRmRule,
)
from app.rules.azure.posture.defender import (
    AzureExposedVulnerableMachineRule,
    AzureMissingEndpointProtectionRule,
)
from app.rules.azure.rbac.privilege import (
    AzurePersonWithSubscriptionControlRule,
    AzureRoleGrantingIdentityRule,
    AzureWorkloadWithSubscriptionControlRule,
)
from app.rules.azure.secrets.key_vault import (
    AzureKeyVaultDeletionRule,
    AzureKeyVaultNetworkRule,
)
from app.rules.azure.storage.public_access import (
    AzurePublicStorageRule,
    AzureStorageEncryptionRule,
    AzureStorageTransportRule,
)
from app.rules.base import SecurityRule

RULE_REGISTRY: list[SecurityRule] = [
    AzureMfaRule(),
    AzurePrivilegedUserRule(),
    AzureDormantPrivilegedAccountRule(),
    AzureLongLivedApplicationCredentialRule(),
    AzurePublicRdpRule(),
    AzurePublicSshRule(),
    AzurePublicWinRmRule(),
    AzureOpenNsgRule(),
    AzurePublicStorageRule(),
    AzureStorageEncryptionRule(),
    AzureStorageTransportRule(),
    AzurePublicDatabaseRule(),
    AzureDatabasePrivateConnectivityRule(),
    AzureDatabaseAuditingRule(),
    AzureLoggingRule(),
    AzureActivityLogExportRule(),
    AzureExposedComputeRule(),
    AzureUnguardedVmRule(),
    AzurePersonWithSubscriptionControlRule(),
    AzureWorkloadWithSubscriptionControlRule(),
    AzureRoleGrantingIdentityRule(),
    AzureKeyVaultDeletionRule(),
    AzureKeyVaultNetworkRule(),
    AzureExposedVulnerableMachineRule(),
    AzureMissingEndpointProtectionRule(),
]


def enabled_rules() -> list[SecurityRule]:
    return list(RULE_REGISTRY)


def get_rule(rule_id: str) -> SecurityRule | None:
    return next((r for r in RULE_REGISTRY if r.rule_id == rule_id), None)


def _assert_unique_rule_ids() -> None:
    """A duplicate rule_id would silently overwrite findings for another rule,
    since findings are keyed on (organization, rule_id, resource)."""
    seen: set[str] = set()
    for rule in RULE_REGISTRY:
        if rule.rule_id in seen:
            raise RuntimeError(f"Duplicate rule_id in registry: {rule.rule_id}")
        seen.add(rule.rule_id)


_assert_unique_rule_ids()
