"""Cloud-neutral domain vocabulary.

These names are shared by the database, the rule engine, the risk engine and
the API. Nothing here is Azure-specific -- adding an AWS connector later must
not require touching this file (ARCHITECTURE.md section 6).
"""

from enum import StrEnum


class Provider(StrEnum):
    AZURE = "azure"
    AWS = "aws"  # extension point only -- no connector in v0.1
    GCP = "gcp"  # extension point only -- no connector in v0.1


class Role(StrEnum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    IT_ADMIN = "IT_ADMIN"
    VIEWER = "VIEWER"
    ADVISOR = "ADVISOR"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Level(StrEnum):
    """Scale shared by criticality, data sensitivity and internet exposure.

    UNKNOWN is a first-class value, not a missing one: the risk engine scores it
    cautiously rather than optimistically (RISK_ENGINE.md section 1).
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class ContextSource(StrEnum):
    """Where a piece of asset context came from.

    Context -- how critical an asset is, how sensitive its data, which
    environment it belongs to -- is the multiplier the risk engine turns a
    finding into a risk with. Until now it arrived with no provenance: a
    CRITICAL that somebody typed into a tag and a CRITICAL inferred from a
    resource name looked identical by the time they reached a score, so a
    customer asking "why is this ranked above that" could be told the arithmetic
    and never the input.

    The members are ordered weakest to strongest, and that order is the whole
    point: :attr:`confidence` puts a number on it, and the context engine uses
    that number to say which of two claims about the same asset it kept.
    """

    # Nothing said anything. Pairs with UNKNOWN, never with a value.
    NONE = "none"
    # CloudGuard worked it out: a resource called "prod-db-01" is probably
    # production, and something in production is probably important. How most
    # small teams actually mark an environment, and wrong often enough to be
    # worth labelling as a deduction rather than a reading. A value derived
    # from another value lands here whatever that other value's source was --
    # the deduction is the weak link, not where its input came from.
    INFERRED = "inferred"
    # True by what the thing is: a database holds data whatever anyone tagged
    # it. A floor rather than a reading, and never wrong in the unsafe
    # direction.
    TYPE_FLOOR = "type_floor"
    # A tag on the asset itself. Somebody meant it once; whether it is still
    # true is between the customer and their automation.
    PROVIDER_TAG = "provider_tag"
    # Declared by the customer on the subscription this asset lives in.
    INHERITED = "inherited"
    # Declared by the customer, about this asset. The only source that is
    # somebody taking responsibility for the answer.
    CUSTOMER = "customer"

    @property
    def confidence(self) -> float:
        """How much weight the claim deserves, on 0..1.

        Derived from the source rather than stored beside it, because a
        confidence that could be set independently would eventually disagree
        with the source it is supposed to describe -- and there is no reading of
        "a naming guess, confidence 0.95" that is worth being able to express.
        """
        return _CONTEXT_CONFIDENCE[self]


_CONTEXT_CONFIDENCE: dict[ContextSource, float] = {
    ContextSource.NONE: 0.0,
    ContextSource.INFERRED: 0.4,
    ContextSource.TYPE_FLOOR: 0.7,
    ContextSource.PROVIDER_TAG: 0.8,
    ContextSource.INHERITED: 0.9,
    ContextSource.CUSTOMER: 1.0,
}


class RuleState(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RuleScope(StrEnum):
    PER_RESOURCE = "per_resource"
    AGGREGATE = "aggregate"


class TaskOutcome(StrEnum):
    """What became of one unit of collection.

    ``PARTIAL`` is the one that carries weight. It means data came back and is
    known to be incomplete -- a truncated listing, a detail call that failed for
    some resources. Rules must treat it exactly as they treat a failure, because
    a list missing an unknown number of entries cannot support "none of them are
    public". It is the UNKNOWN/PASS distinction, one layer below the rules.
    """

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    # Its input never arrived, so it was never attempted. Distinct from FAILED:
    # nothing is known to be wrong with this task, and saying otherwise would
    # send someone looking for a problem that is one hop away.
    SKIPPED = "SKIPPED"

    @property
    def is_trustworthy(self) -> bool:
        """Whether conclusions may be drawn from this task's data."""
        return self is TaskOutcome.COMPLETE


class CollectionScope(StrEnum):
    """What a unit of collection is a reading *of*.

    Not a naming distinction. A subscription's resources and a tenant's
    directory are collected against different scopes, and collecting the second
    once per subscription is how one administrator without MFA became one
    finding per subscription: the directory is the same directory each time, so
    every subscription contributed its own copy of every user.

    ``ACCOUNT`` is per subscription; ``DIRECTORY`` is per tenant, gathered once
    for the whole scan however many subscriptions it covers.
    """

    ACCOUNT = "account"
    DIRECTORY = "directory"


class ScanTrigger(StrEnum):
    """Why a scan ran.

    ``triggered_by_user_id`` used to carry this by implication, and stopped
    being able to the moment scans could start themselves: a manual scan whose
    user record had since gone looked exactly like a scheduled one. Stating it
    is cheaper than inferring it.
    """

    MANUAL = "MANUAL"
    SCHEDULED = "SCHEDULED"
    # CloudGuard checking whether a fix the customer reported actually took.
    # Distinct from SCHEDULED because it answers a question somebody asked, and
    # from MANUAL because they asked it by marking work done rather than by
    # pressing scan -- and because it retries on a backoff nobody sees.
    VERIFICATION = "VERIFICATION"


class ScanStepKind(StrEnum):
    """The stages a scan runs as separately durable units.

    Three, not a general DAG. A scan's shape is decided in code and has been
    the same shape since the pipeline existed -- resolve what to read, read it,
    interpret it -- so edges between arbitrary steps would be a mechanism with
    one configuration, and cycle checking for a graph nobody can author.
    Ordering by kind says the same thing in a query.
    """

    # Resolve what this scan covers, and create the COLLECT steps for it.
    # A step rather than work done at queue time, because the scope must be
    # resolved when the scan runs: a subscription discovered or excluded while
    # the scan sat in the queue should be picked up or left out accordingly.
    PLAN = "PLAN"
    # Read one scope -- one subscription, or the tenant directory -- and store
    # what came back. One step each, so a tenant of fifty subscriptions is
    # fifty retryable units rather than one that has to survive them all.
    COLLECT = "COLLECT"
    # Interpret every capture this scan stored: normalize, evaluate, score,
    # verify. Runs once the COLLECT steps have settled, which is not the same
    # as having succeeded -- a subscription CloudGuard could not read is a gap
    # in the report, never a reason to withhold the rest of it.
    ANALYZE = "ANALYZE"


class ScanStepStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    # Its input never arrived. Distinct from FAILED for the same reason the
    # collection executor draws that line: nothing is known to be wrong with
    # this step, and saying otherwise sends someone looking one hop away from
    # the real problem.
    SKIPPED = "SKIPPED"

    @property
    def is_terminal(self) -> bool:
        return self in {
            ScanStepStatus.SUCCEEDED,
            ScanStepStatus.FAILED,
            ScanStepStatus.SKIPPED,
        }

    @property
    def is_settled(self) -> bool:
        """Whether this step will do no more work.

        The condition ANALYZE waits on. Deliberately not "succeeded": a scan
        whose storage listing failed still has everything else to say, and
        holding the whole report back over one unreadable subscription would
        turn a partial answer into no answer.
        """
        return self.is_terminal


class ScanStatus(StrEnum):
    QUEUED = "QUEUED"
    DISCOVERING = "DISCOVERING"
    NORMALIZING = "NORMALIZING"
    EVALUATING = "EVALUATING"
    CALCULATING_RISK = "CALCULATING_RISK"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    CANCELLED = "CANCELLED"

    @property
    def is_terminal(self) -> bool:
        return self in {
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            ScanStatus.PARTIAL,
            ScanStatus.CANCELLED,
        }


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"

    @property
    def is_open(self) -> bool:
        """Statuses that still count against the org security score."""
        return self in {FindingStatus.OPEN, FindingStatus.IN_PROGRESS}


class RiskKind(StrEnum):
    """What a risk is a risk *about*.

    A finding risk is one observation, scored for the asset it was made on. A
    scenario risk is several of them seen as one thing -- a route from somewhere
    an attacker could start to something worth taking -- and it ranks above any
    of its parts because the combination is worse than the sum.
    """

    FINDING = "FINDING"
    ATTACK_PATH = "ATTACK_PATH"


class RiskStatus(StrEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    ACCEPTED = "ACCEPTED"


class RemediationStatus(StrEnum):
    TODO = "TODO"
    IN_PROGRESS = "IN_PROGRESS"
    DONE = "DONE"
    CANCELLED = "CANCELLED"


class VerificationStatus(StrEnum):
    """What became of a fix the customer said they had made.

    The reason this is not a boolean: "not verified" covers three different
    situations that need three different sentences. The fix might not have
    worked; CloudGuard might not have been able to look; or it might simply be
    too soon, because a cloud takes its time agreeing with itself and a check
    run thirty seconds after a change reports the environment as it was.

    Collapsing those into one answer is what makes a verification feature
    untrustworthy: a customer told "still failing" who has in fact fixed it
    stops believing the next answer too.
    """

    # Being checked. The fix is claimed, and CloudGuard has not yet seen enough
    # to agree or disagree.
    PENDING = "PENDING"
    # A rule that used to fail returned an explicit PASS over the same asset.
    VERIFIED = "VERIFIED"
    # CloudGuard looked, repeatedly, and the check still fails.
    STILL_FAILING = "STILL_FAILING"
    # CloudGuard looked and could not tell -- the evidence the rule needs never
    # arrived. Not the same as failing, and never reported as if it were: this
    # is a gap in what CloudGuard could see, which is CloudGuard's problem to
    # explain rather than the customer's to fix.
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    # The question stopped being worth asking: the finding was accepted as a
    # risk, or the asset it was about is gone.
    ABANDONED = "ABANDONED"

    @property
    def is_settled(self) -> bool:
        return self is not VerificationStatus.PENDING


class Priority(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConnectionScope(StrEnum):
    """How much of a customer's cloud one connection covers.

    The choice is a real trade between coverage and least privilege, and it is
    the customer's to make: TENANT_ROOT sees every subscription that exists now
    or later and needs a correspondingly broad grant, while SUBSCRIPTION is the
    narrowest thing that works. CloudGuard does not pick for them.
    """

    TENANT_ROOT = "TENANT_ROOT"
    MANAGEMENT_GROUP = "MANAGEMENT_GROUP"
    SUBSCRIPTION = "SUBSCRIPTION"



class ConsentStatus(StrEnum):
    PENDING = "PENDING"
    GRANTED = "GRANTED"
    REVOKED = "REVOKED"


class CloudAccountStatus(StrEnum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    ERROR = "ERROR"
    DISABLED = "DISABLED"


class ExceptionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class ResourceType(StrEnum):
    """Normalized, cloud-neutral resource types.

    The Azure normalizer maps ARM type strings onto these; an AWS normalizer
    would map its own. Rules declare ``applies_to`` in these terms so rule code
    never sees a provider-specific type string.
    """

    SUBSCRIPTION = "subscription"
    RESOURCE_GROUP = "resource_group"
    VIRTUAL_MACHINE = "virtual_machine"
    NETWORK_SECURITY_GROUP = "network_security_group"
    NETWORK_INTERFACE = "network_interface"
    PUBLIC_IP = "public_ip"
    VIRTUAL_NETWORK = "virtual_network"
    SUBNET = "subnet"
    STORAGE_ACCOUNT = "storage_account"
    SQL_SERVER = "sql_server"
    SQL_DATABASE = "sql_database"
    POSTGRESQL_SERVER = "postgresql_server"
    USER = "user"
    # An identity that is not a person: a service principal, or the managed
    # identity attached to a resource. Distinct from USER because the
    # remediation differs entirely -- a person gets MFA, a workload identity
    # gets a narrower role.
    SERVICE_PRINCIPAL = "service_principal"
    ROLE_ASSIGNMENT = "role_assignment"
    DIAGNOSTIC_SETTING = "diagnostic_setting"
    UNKNOWN = "unknown"


class RelationshipType(StrEnum):
    """How two assets are related, and what that lets someone do.

    The first four are structural: they describe how an environment is put
    together. The last two are *capability* edges -- they describe what an
    identity is able to reach -- and the difference matters because only the
    second kind composes into a path. Knowing an NSG protects a VM tells you
    about configuration; knowing that VM's identity grants Contributor over the
    subscription tells you what happens if the VM is taken.
    """

    ATTACHED_TO = "attached_to"
    CONTAINS = "contains"
    PROTECTS = "protects"
    ASSIGNED_TO = "assigned_to"

    # A resource runs as this identity. The first hop from a compromised
    # workload to everything that workload is allowed to do.
    HAS_IDENTITY = "has_identity"
    # This identity holds a role over that scope. The hop that turns a foothold
    # into a blast radius.
    GRANTS_ROLE = "grants_role"

    @property
    def is_capability(self) -> bool:
        """Whether traversing this edge means gaining reach.

        Structural edges are not walked when working out what an attacker
        reaches: an NSG protecting a VM is a fact about the VM, not a way to get
        anywhere from the NSG.
        """
        return self in {RelationshipType.HAS_IDENTITY, RelationshipType.GRANTS_ROLE,
                        RelationshipType.CONTAINS}
