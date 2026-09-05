"""The rule registry — the single source of truth for what CloudGuard checks.

The ``rules`` database table is a read-mirror of this list, synced at startup.
Adding a rule means adding it here and writing its tests; it never means
inserting a database row (RULE_ENGINE.md section 4).
"""

from app.rules.aws.compute.exposure import AwsInstanceMetadataRule
from app.rules.aws.database.exposure import (
    AwsDatabaseEncryptionRule,
    AwsDatabasePatchingRule,
    AwsPublicDatabaseRule,
)
from app.rules.aws.identity.credentials import (
    AwsAccessAnalyzerRule,
    AwsAdministratorPolicyRule,
    AwsExpiredCertificateRule,
    AwsPasswordPolicyRule,
    AwsRootAccessKeyRule,
    AwsRootMfaRule,
    AwsStaleAccessKeyRule,
    AwsUserWithoutMfaRule,
)
from app.rules.aws.logging.trails import (
    AwsCloudTrailCoverageRule,
    AwsConfigRecorderRule,
    AwsEbsDefaultEncryptionRule,
    AwsFlowLogRule,
    AwsRootUsageMonitoringRule,
    AwsTrailBucketLoggingRule,
    AwsTrailEncryptionRule,
    AwsTrailValidationRule,
    AwsUnauthorizedApiMonitoringRule,
)
from app.rules.aws.network.exposure import (
    AwsDefaultSecurityGroupRule,
    AwsOpenNetworkAclRule,
    AwsPublicDatabasePortRule,
    AwsPublicRdpRule,
    AwsPublicSshRule,
)
from app.rules.aws.posture.coverage import AwsGuardDutyRule, AwsSecurityHubRule
from app.rules.aws.secrets.keys import AwsKeyRotationRule
from app.rules.aws.storage.public_access import (
    AwsBucketEncryptionRule,
    AwsBucketTransportRule,
    AwsPublicBucketRule,
)
from app.rules.azure.compute.exposure import (
    AzureExposedComputeRule,
    AzureUnguardedVmRule,
)
from app.rules.azure.database.encryption import AzureDatabaseEncryptionRule
from app.rules.azure.database.public_access import (
    AzureDatabaseAuditingRule,
    AzureDatabasePrivateConnectivityRule,
    AzurePublicDatabaseRule,
)
from app.rules.azure.identity.credentials import (
    AzureLongLivedApplicationCredentialRule,
)
from app.rules.azure.identity.dormant import AzureDormantPrivilegedAccountRule
from app.rules.azure.identity.mfa import (
    AzureLegacyAuthenticationRule,
    AzureMfaRule,
    AzureTenantMfaEnforcementRule,
    AzureUserWithoutMfaRule,
)
from app.rules.azure.identity.privileged import (
    AzureDisabledPrivilegedUserRule,
    AzureGuestPrivilegedUserRule,
    AzurePrivilegedUserRule,
)
from app.rules.azure.logging.diagnostics import (
    AzureActivityLogExportRule,
    AzureCriticalResourceLoggingRule,
    AzureLoggingRule,
)
from app.rules.azure.network.exposure import (
    AzureOpenNsgRule,
    AzurePublicRdpRule,
    AzurePublicSmbRule,
    AzurePublicSqlPortRule,
    AzurePublicSshRule,
    AzurePublicWinRmRule,
    AzureSensitivePublicAddressRule,
)
from app.rules.azure.posture.defender import (
    AzureExposedVulnerableMachineRule,
    AzureMissingEndpointProtectionRule,
)
from app.rules.azure.rbac.privilege import (
    AzureBroadScopeAssignmentRule,
    AzureDangerousCustomRoleRule,
    AzureExcessiveOwnersRule,
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
    AzureUserWithoutMfaRule(),
    AzureTenantMfaEnforcementRule(),
    AzureLegacyAuthenticationRule(),
    AzureGuestPrivilegedUserRule(),
    AzureDisabledPrivilegedUserRule(),
    AzurePrivilegedUserRule(),
    AzureDormantPrivilegedAccountRule(),
    AzureLongLivedApplicationCredentialRule(),
    AzurePublicRdpRule(),
    AzurePublicSshRule(),
    AzurePublicWinRmRule(),
    AzurePublicSqlPortRule(),
    AzurePublicSmbRule(),
    AzureSensitivePublicAddressRule(),
    AzureOpenNsgRule(),
    AzurePublicStorageRule(),
    AzureStorageEncryptionRule(),
    AzureStorageTransportRule(),
    AzurePublicDatabaseRule(),
    AzureDatabasePrivateConnectivityRule(),
    AzureDatabaseAuditingRule(),
    AzureDatabaseEncryptionRule(),
    AzureLoggingRule(),
    AzureCriticalResourceLoggingRule(),
    AzureActivityLogExportRule(),
    AzureExposedComputeRule(),
    AzureUnguardedVmRule(),
    AzurePersonWithSubscriptionControlRule(),
    AzureWorkloadWithSubscriptionControlRule(),
    AzureRoleGrantingIdentityRule(),
    AzureExcessiveOwnersRule(),
    AzureBroadScopeAssignmentRule(),
    AzureDangerousCustomRoleRule(),
    AzureKeyVaultDeletionRule(),
    AzureKeyVaultNetworkRule(),
    AzureExposedVulnerableMachineRule(),
    AzureMissingEndpointProtectionRule(),
    # AWS. Separate rules over the same neutral resource types, never one rule
    # branching on provider: ``remediation`` is snapshot-copied onto every
    # finding, and ``aws s3api put-public-access-block`` is not a variant of
    # ``az storage account update`` (MULTI_CLOUD.md section 6).
    AwsPublicBucketRule(),
    AwsBucketEncryptionRule(),
    AwsBucketTransportRule(),
    AwsPublicSshRule(),
    AwsPublicRdpRule(),
    AwsPublicDatabasePortRule(),
    AwsOpenNetworkAclRule(),
    AwsDefaultSecurityGroupRule(),
    AwsPublicDatabaseRule(),
    AwsDatabaseEncryptionRule(),
    AwsDatabasePatchingRule(),
    AwsUserWithoutMfaRule(),
    AwsRootAccessKeyRule(),
    AwsRootMfaRule(),
    AwsStaleAccessKeyRule(),
    AwsPasswordPolicyRule(),
    AwsAdministratorPolicyRule(),
    AwsExpiredCertificateRule(),
    AwsAccessAnalyzerRule(),
    AwsInstanceMetadataRule(),
    AwsKeyRotationRule(),
    AwsCloudTrailCoverageRule(),
    AwsTrailValidationRule(),
    AwsTrailEncryptionRule(),
    AwsTrailBucketLoggingRule(),
    AwsConfigRecorderRule(),
    AwsFlowLogRule(),
    AwsUnauthorizedApiMonitoringRule(),
    AwsRootUsageMonitoringRule(),
    AwsEbsDefaultEncryptionRule(),
    AwsGuardDutyRule(),
    AwsSecurityHubRule(),
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
