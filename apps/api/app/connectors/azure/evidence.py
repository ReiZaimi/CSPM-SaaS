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

from datetime import timedelta

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

    @property
    def reuse_window(self) -> timedelta | None:
        return _REUSE_WINDOWS.get(self)


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


# Evidence CloudGuard collects because the product needs it, not because a rule
# judges it. Every other key in the plans above is named by some rule's
# ``requires_evidence``; these three are named by none, and would therefore be
# dropped the moment a plan is derived from the rule set rather than written out
# by hand.
#
# They are not leftovers. Inventory is what the customer's asset list is made
# of -- the one reading that covers resource types no rule has been written for
# yet -- and the two authorization listings are what the asset graph's identity
# edges are built from: who holds which role, and what that role permits. No
# rule reads any of them, and dropping them would cost the customer their
# inventory and every privilege path in one go.
#
# Declared here rather than inferred, because "no rule needs it" and "nothing
# needs it" are different statements and only the second is a reason to stop
# collecting.
BASELINE_EVIDENCE: frozenset[AzureEvidence] = frozenset(
    {
        AzureEvidence.RESOURCES,
        AzureEvidence.ROLE_ASSIGNMENTS,
        AzureEvidence.ROLE_DEFINITIONS,
    }
)

# How old a complete reading may be and still be carried into a later scan
# instead of re-read. Absent means never, which is the answer for all but one
# key and the right default (``EvidenceKey.reuse_window``).
#
# Role *definitions* are the exception, and only because of what they are: the
# catalogue of what each role permits, overwhelmingly Azure's own built-ins,
# several hundred rows per subscription that change when Microsoft ships a new
# role. No rule reads them -- they label the graph's identity edges -- so a
# stale definition cannot turn a FAIL into a PASS or a PASS into a FAIL. The
# worst a week-old catalogue can do is describe a freshly edited custom role by
# its previous permissions, in the label on an edge whose existence is decided
# by the role *assignment*, which is read fresh every scan.
#
# Role assignments are deliberately not here, for that same reason inverted:
# they are who can do what, they change constantly, and every privilege path in
# the graph is drawn from them.
_REUSE_WINDOWS: dict[AzureEvidence, timedelta] = {
    AzureEvidence.ROLE_DEFINITIONS: timedelta(days=7),
}


def keys_in(category: EvidenceCategory) -> frozenset[AzureEvidence]:
    """Every key that belongs to one category.

    Used where a category-level fact has to be applied to the keys underneath
    it -- a stale role grants no permission for a whole category, and the rules
    that lost their verdict did so one key at a time.
    """
    return frozenset(key for key, value in _CATEGORIES.items() if value is category)
