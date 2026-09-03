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
    # Whether each server records who queried it. Its own key rather than part
    # of the listing above, because a key is the unit a rule depends on and
    # these two are separately deniable: the auditing read arrived in role v4,
    # so a customer who has not redeployed reads their servers and firewall
    # rules perfectly well and gets a 403 here. Folded together, that 403 cost
    # the public-access rule its verdict as well -- a gap CloudGuard invented,
    # which is the same mistake ``requires_evidence`` was introduced to stop
    # one layer up.
    SQL_AUDITING = "sql_auditing"
    POSTGRESQL_SERVERS = "postgresql_servers"

    # The vault's configuration. Never its contents -- reading a secret is a
    # data-plane permission this connector does not hold.
    KEY_VAULTS = "key_vaults"

    # Microsoft Defender for Cloud's own assessments of this subscription.
    #
    # The one reading that is somebody else's conclusion rather than a
    # configuration. CloudGuard does not re-report them: it reads them as
    # evidence and reaches its own verdict, which is what lets a vulnerability
    # finding become "on an internet-facing machine" -- a sentence Defender has
    # the finding for and CloudGuard has the exposure for, and neither says
    # alone.
    SECURITY_ASSESSMENTS = "security_assessments"

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

    # Defences rather than faults. Neither produces a finding of its own; both
    # are read so a rule can tell whether something already stands between an
    # attacker and the misconfiguration it found (``rules/controls.py``).
    #
    # Both come from Graph under ``Policy.Read.All``, which is already in
    # ``REQUIRED_GRAPH_PERMISSIONS`` and already consented by every connected
    # tenant -- so this costs no customer a second trip to a Global
    # Administrator.
    SECURITY_DEFAULTS = "security_defaults"
    CONDITIONAL_ACCESS_POLICIES = "conditional_access_policies"

    # The credentials on this tenant's own application registrations: client
    # secrets and certificates, with the dates they stop working.
    #
    # Read under ``Application.Read.All``, which admin consent has requested
    # since onboarding existed and no collector has ever used -- so this costs
    # no customer a second trip to a Global Administrator
    # (``DECISIONS.md`` section 63).
    APPLICATION_CREDENTIALS = "application_credentials"

    # When each account last signed in. Its own key rather than a wider
    # ``users`` listing, because it is separately deniable in a way none of the
    # other directory reads are: ``signInActivity`` needs an Entra ID P1 or P2
    # licence, so a fully consented tenant on the free tier reads its users,
    # roles and policies perfectly well and is refused exactly this. Folded
    # into ``USERS``, that refusal would cost the MFA rule its verdict over a
    # licence that has nothing to do with it.
    USER_SIGN_IN_ACTIVITY = "user_sign_in_activity"

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
    AzureEvidence.SQL_AUDITING: EvidenceCategory.DATABASE,
    AzureEvidence.KEY_VAULTS: EvidenceCategory.SECRETS,
    AzureEvidence.SECURITY_ASSESSMENTS: EvidenceCategory.POSTURE,
    AzureEvidence.POSTGRESQL_SERVERS: EvidenceCategory.DATABASE,
    AzureEvidence.DIAGNOSTIC_SETTINGS: EvidenceCategory.LOGGING,
    AzureEvidence.ROLE_ASSIGNMENTS: EvidenceCategory.AUTHORIZATION,
    AzureEvidence.ROLE_DEFINITIONS: EvidenceCategory.AUTHORIZATION,
    AzureEvidence.USERS: EvidenceCategory.IDENTITY,
    AzureEvidence.DIRECTORY_ROLES: EvidenceCategory.IDENTITY,
    AzureEvidence.USER_ROLE_MAP: EvidenceCategory.IDENTITY,
    AzureEvidence.SECURITY_DEFAULTS: EvidenceCategory.IDENTITY,
    AzureEvidence.CONDITIONAL_ACCESS_POLICIES: EvidenceCategory.IDENTITY,
    AzureEvidence.APPLICATION_CREDENTIALS: EvidenceCategory.IDENTITY,
    AzureEvidence.USER_SIGN_IN_ACTIVITY: EvidenceCategory.IDENTITY,
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
# ``requires_evidence``; these are named by none, and would therefore be dropped
# the moment a plan is derived from the rule set rather than written out by
# hand.
#
# The authorization listings earn their place plainly: they are what the asset
# graph's identity edges are built from -- who holds which role, and what that
# role permits -- so dropping them costs every privilege path at once. The two
# control readings earn theirs the same way, as the defences that lower a
# finding's score rather than raise one.
#
# ``RESOURCES`` is the one to be honest about. This comment used to claim the
# customer's asset list was made of it. It is not: every asset CloudGuard shows
# comes from the per-service listings -- the storage listing, the SQL listing,
# the virtual machine listing -- normalized into ``cloud_resources``. The
# Resource Graph payload is stored verbatim in the snapshot and read by nothing,
# today, anywhere.
#
# It is kept because of what it is rather than what it does: the only reading
# that covers the resource types no rule has been written for, which is the
# evidence behind the sentence the product cannot yet say -- "you have forty
# resources CloudGuard does not check". Until something says that, this is a
# query per subscription per scan and a stored blob for a capability that does
# not exist, and the honest options are to build it or to stop asking.
#
# Declared here rather than inferred, because "no rule needs it" and "nothing
# needs it" are different statements and only the second is a reason to stop
# collecting.
BASELINE_EVIDENCE: frozenset[AzureEvidence] = frozenset(
    {
        AzureEvidence.RESOURCES,
        AzureEvidence.ROLE_ASSIGNMENTS,
        AzureEvidence.ROLE_DEFINITIONS,
        # The two control readings. No rule *requires* them -- a rule that did
        # would report UNKNOWN when a defence could not be read, which is
        # backwards: an unreadable control is an absent one, and the finding
        # keeps its full score. They are collected because the score is worse
        # without them, not because a verdict depends on them.
        AzureEvidence.SECURITY_DEFAULTS,
        AzureEvidence.CONDITIONAL_ACCESS_POLICIES,
    }
)

# How old a complete reading may be and still be carried into a later scan
# instead of re-read. Absent means never, which is now the answer for every key.
#
# Role definitions used to carry a week, on the stated grounds that no rule read
# them -- they only labelled the graph's identity edges, so a stale catalogue
# could not turn a FAIL into a PASS. AZ-IAM-003 made that false. It asks whether
# a role permits writing role assignments, which is a fact about the definition's
# permissions, so a customer who edits a custom role to remove that action and
# rescans to check would be answered from the catalogue as it stood a week
# before the edit. That is the exact shape of "verified fixed" being untrue, and
# the window is worth less than the guarantee.
#
# ``test_no_rule_reads_evidence_that_may_be_carried_forward`` is what caught it,
# and is why this dict is empty rather than merely smaller.
_REUSE_WINDOWS: dict[AzureEvidence, timedelta] = {}


def keys_in(category: EvidenceCategory) -> frozenset[AzureEvidence]:
    """Every key that belongs to one category.

    Used where a category-level fact has to be applied to the keys underneath
    it -- a stale role grants no permission for a whole category, and the rules
    that lost their verdict did so one key at a time.
    """
    return frozenset(key for key, value in _CATEGORIES.items() if value is category)
