"""The rule registry — the single source of truth for what CloudGuard checks.

The ``rules`` database table is a read-mirror of this list, synced at startup.
Adding a rule means adding it here and writing its tests; it never means
inserting a database row (RULE_ENGINE.md section 4).
"""

from app.rules.azure.compute.exposure import AzureExposedComputeRule
from app.rules.azure.database.public_access import AzurePublicDatabaseRule
from app.rules.azure.identity.mfa import AzureMfaRule
from app.rules.azure.identity.privileged import AzurePrivilegedUserRule
from app.rules.azure.logging.diagnostics import AzureLoggingRule
from app.rules.azure.network.exposure import (
    AzureOpenNsgRule,
    AzurePublicRdpRule,
    AzurePublicSshRule,
)
from app.rules.azure.storage.public_access import (
    AzurePublicStorageRule,
    AzureStorageEncryptionRule,
)
from app.rules.base import SecurityRule

RULE_REGISTRY: list[SecurityRule] = [
    AzureMfaRule(),
    AzurePrivilegedUserRule(),
    AzurePublicRdpRule(),
    AzurePublicSshRule(),
    AzureOpenNsgRule(),
    AzurePublicStorageRule(),
    AzureStorageEncryptionRule(),
    AzurePublicDatabaseRule(),
    AzureLoggingRule(),
    AzureExposedComputeRule(),
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
