"""Every unit of evidence CloudGuard collects from Azure.

One member per collection task. The task declares which it produces, the rule
declares which it needs, and the executor's coverage report is keyed by the same
values -- so "this rule lost its verdict because that listing failed" is one
lookup rather than three strings agreeing by hand.

Each key knows its own category. Tasks therefore do not declare one, which
removes the way the two used to drift: a task whose key said storage and whose
category said network was a perfectly valid thing to write, and the only symptom
was a rule that quietly never degraded.
"""

from app.connectors.evidence import EvidenceCategory, EvidenceKey


class AzureEvidence(EvidenceKey):
    """The keys. Values match the snapshot's own payload keys, deliberately.

    A snapshot holds ``{"storage_accounts": [...]}``, so keeping the key equal
    to the payload name means the evidence a rule asks for and the data it then
    reads are named the same thing in both places.
    """

    # Resource Graph inventory: everything in the subscription, unjudged.
    RESOURCES = "resources"

    NETWORK_SECURITY_GROUPS = "network_security_groups"
    NETWORK_INTERFACES = "network_interfaces"
    PUBLIC_IP_ADDRESSES = "public_ip_addresses"

    VIRTUAL_MACHINES = "virtual_machines"

    STORAGE_ACCOUNTS = "storage_accounts"

    SQL_SERVERS = "sql_servers"
    POSTGRESQL_SERVERS = "postgresql_servers"

    DIAGNOSTIC_SETTINGS = "diagnostic_settings"

    # Who may act on what, within this subscription. Read from ARM under the
    # scanner role, unlike the directory keys below, which come from Graph
    # under admin consent -- two grants that fail independently.
    ROLE_ASSIGNMENTS = "role_assignments"
    ROLE_DEFINITIONS = "role_definitions"

    # Directory. Read once per scan against the tenant, never per subscription.
    USERS = "users"
    DIRECTORY_ROLES = "directory_roles"
    USER_ROLE_MAP = "user_role_map"

    @property
    def category(self) -> EvidenceCategory:
        return _CATEGORIES[self]


_CATEGORIES: dict[AzureEvidence, EvidenceCategory] = {
    AzureEvidence.RESOURCES: EvidenceCategory.RESOURCES,
    AzureEvidence.NETWORK_SECURITY_GROUPS: EvidenceCategory.NETWORK,
    AzureEvidence.NETWORK_INTERFACES: EvidenceCategory.NETWORK,
    AzureEvidence.PUBLIC_IP_ADDRESSES: EvidenceCategory.NETWORK,
    AzureEvidence.VIRTUAL_MACHINES: EvidenceCategory.COMPUTE,
    AzureEvidence.STORAGE_ACCOUNTS: EvidenceCategory.STORAGE,
    AzureEvidence.SQL_SERVERS: EvidenceCategory.DATABASE,
    AzureEvidence.POSTGRESQL_SERVERS: EvidenceCategory.DATABASE,
    AzureEvidence.DIAGNOSTIC_SETTINGS: EvidenceCategory.LOGGING,
    AzureEvidence.ROLE_ASSIGNMENTS: EvidenceCategory.AUTHORIZATION,
    AzureEvidence.ROLE_DEFINITIONS: EvidenceCategory.AUTHORIZATION,
    AzureEvidence.USERS: EvidenceCategory.IDENTITY,
    AzureEvidence.DIRECTORY_ROLES: EvidenceCategory.IDENTITY,
    AzureEvidence.USER_ROLE_MAP: EvidenceCategory.IDENTITY,
}

# Enumerated rather than compared at call time: a key added without a category
# would otherwise fail as a KeyError inside a running scan, on the one path
# whose job is to be reliable when everything else is not.
_missing = set(AzureEvidence) - set(_CATEGORIES)
if _missing:  # pragma: no cover - import-time guard
    raise RuntimeError(
        "AzureEvidence members with no category: " + ", ".join(sorted(_missing))
    )


def keys_in(category: EvidenceCategory) -> frozenset[AzureEvidence]:
    """Every key that belongs to one category.

    Used where a category-level fact has to be applied to the keys underneath
    it -- a stale role grants no permission for a whole category, and the rules
    that lost their verdict did so one key at a time.
    """
    return frozenset(key for key, value in _CATEGORIES.items() if value is category)
