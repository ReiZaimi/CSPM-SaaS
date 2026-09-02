"""The rule contract.

Rules are deterministic functions of a snapshot. No network, no database, no
LLM -- given the same normalized input a rule must always return the same
result, or "CloudGuard verified the fix" would mean nothing.

The four states are not three states plus an error case:

* ``PASS``            -- we looked, and it is fine.
* ``FAIL``            -- we looked, and it is wrong. Becomes a Finding.
* ``UNKNOWN``         -- we could not look. Never a Finding, never a PASS.
* ``NOT_APPLICABLE``  -- the rule has nothing to say about this resource.

The UNKNOWN/PASS distinction is the one that carries the most weight. A storage
API that timed out must not quietly read as "no public storage found".
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from app.connectors.evidence import EvidenceKey
from app.core.enums import Provider, ResourceType, RuleScope, RuleState, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.risk.grouping import RiskGrouping


@dataclass(frozen=True)
class RuleResult:
    state: RuleState
    evidence: dict[str, Any] | None = None
    message: str | None = None
    # Required when an AGGREGATE rule emits several results, so each one can be
    # attributed to the resource it concerns.
    resource_id: str | None = None
    # How exploitable *this* instance is, where the rule can tell that it is
    # less than the worst case its class tag describes.
    #
    # ``None`` means the rule has nothing instance-specific to say and the class
    # tag stands. A value is only ever a step down: see
    # :attr:`SecurityRule.exploitability`.
    exploitability: int | None = None

    @classmethod
    def passed(cls, evidence: dict[str, Any] | None = None, **kw: Any) -> "RuleResult":
        return cls(state=RuleState.PASS, evidence=evidence, **kw)

    @classmethod
    def failed(
        cls, evidence: dict[str, Any] | None = None, message: str | None = None, **kw: Any
    ) -> "RuleResult":
        return cls(state=RuleState.FAIL, evidence=evidence, message=message, **kw)

    @classmethod
    def unknown(cls, reason: str, **kw: Any) -> "RuleResult":
        return cls(state=RuleState.UNKNOWN, message=reason, **kw)

    @classmethod
    def not_applicable(cls, message: str | None = None, **kw: Any) -> "RuleResult":
        return cls(state=RuleState.NOT_APPLICABLE, message=message, **kw)


@dataclass
class RuleContext:
    """Everything a rule is allowed to see: this scan's normalized state.

    Not a database handle and not an API client -- a rule that could call Azure
    directly would be neither reproducible nor testable.
    """

    resources: list[CloudResource] = field(default_factory=list)
    # (source_id, relationship_type) -> [target_id]
    relationships: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    # Evidence keys that could not be relied on this scan, e.g.
    # {"storage_accounts": "timeout"}. Rules whose evidence is missing degrade
    # to UNKNOWN instead of guessing.
    #
    # Keyed per evidence key rather than per category, which is finer than it
    # sounds: a subscription whose PostgreSQL listing failed has read its SQL
    # servers perfectly well, and degrading the SQL rule over its sibling would
    # be a gap CloudGuard invented rather than one it found.
    collection_errors: dict[str, str] = field(default_factory=dict)

    _by_id: dict[str, CloudResource] = field(default_factory=dict, init=False, repr=False)
    _inverse: dict[tuple[str, str], list[str]] = field(
        default_factory=dict, init=False, repr=False
    )

    def __post_init__(self) -> None:
        self._by_id = {r.provider_resource_id: r for r in self.resources}
        # Edges are stored once, in their natural direction (an NSG *protects* a
        # VM). Both endpoints need to ask about them, though, so the reverse
        # index is derived here rather than duplicating edges at write time.
        self._inverse = {}
        for (source, rel_type), targets in self.relationships.items():
            for target in targets:
                self._inverse.setdefault((target, rel_type), []).append(source)

    def get_resource(self, resource_id: str) -> CloudResource | None:
        return self._by_id.get(resource_id)

    def get_resources_by_type(self, resource_type: ResourceType) -> list[CloudResource]:
        return [r for r in self.resources if r.resource_type == resource_type]

    def get_related(
        self, resource: CloudResource, relationship_type: str
    ) -> list[CloudResource]:
        """Follow edges outward: "what does this resource point at?"""
        ids = self.relationships.get((resource.provider_resource_id, relationship_type), [])
        return [self._by_id[i] for i in ids if i in self._by_id]

    def get_related_inverse(
        self, resource: CloudResource, relationship_type: str
    ) -> list[CloudResource]:
        """Follow edges inward: "what points at this resource?"

        Lets AZ-CMP-001 ask a VM which NSGs guard it, using the same edges
        AZ-NET-001 uses to ask an NSG what it is attached to.
        """
        ids = self._inverse.get((resource.provider_resource_id, relationship_type), [])
        return [self._by_id[i] for i in ids if i in self._by_id]

    def has_collection_error(self, *keys: EvidenceKey) -> str | None:
        """Why one of these pieces of evidence cannot be relied on, if any.

        Takes evidence keys rather than strings. That is the whole point of the
        typed keys: the previous signature accepted anything, so
        ``has_collection_error("identity", "mfa")`` was a perfectly valid call
        that half checked nothing -- no task has ever produced ``mfa`` -- and
        the symptom was a rule that would not have degraded if that evidence
        had gone missing.
        """
        for key in keys:
            if key.value in self.collection_errors:
                return self.collection_errors[key.value]
        return None

    def for_provider(self, provider: Provider) -> "RuleContext":
        """This context narrowed to one cloud.

        ``matches`` keeps a per-resource rule away from another provider's
        resources, but an AGGREGATE rule never goes through it -- it reads
        ``resources`` and ``get_resources_by_type`` directly, and a
        cloud-neutral resource type would hand it another cloud's inventory. An
        Azure MFA rule counting AWS IAM users would be wrong in a way nothing
        downstream could detect.

        Returns ``self`` unchanged when everything already belongs to that
        provider, which is every scan today.
        """
        if all(r.provider == provider for r in self.resources):
            return self

        kept = [r for r in self.resources if r.provider == provider]
        ids = {r.provider_resource_id for r in kept}
        return RuleContext(
            resources=kept,
            relationships={
                (source, rel): [t for t in targets if t in ids]
                for (source, rel), targets in self.relationships.items()
                if source in ids
            },
            collection_errors=self.collection_errors,
        )


class SecurityRule(ABC):
    """Base class for every rule. Subclasses declare metadata, then evaluate."""

    rule_id: str
    name: str
    description: str
    category: str
    provider: Provider = Provider.AZURE
    severity: Severity
    version: str = "1.0"
    # How exploitable the *worst* instance of this misconfiguration is, 0-5,
    # feeding the risk formula (RISK_ENGINE.md section 1). The scale is what an
    # attacker must already have:
    #
    #   5  nothing -- anonymous, from the internet, today
    #   4  a credential of the kind routinely phished or sprayed, or a
    #      guessable identifier
    #   3  a valid credential, or an existing foothold in the environment
    #   2  a foothold plus a particular position: a role, a host, a network
    #   1  no exploitation on its own -- it weakens detection or defence in
    #      depth, and makes another step easier
    #   0  not exploitable
    #
    # Required, with no default. A default of 0 meant a rule whose author never
    # thought about this silently asserted "not exploitable" -- the same
    # overclaim as a PASS nobody earned, and the one this engine refuses
    # everywhere else. ``severity`` above is declared the same way for the same
    # reason.
    #
    # A ceiling rather than a constant. Where the evidence shows one instance is
    # less exploitable than the worst case -- an NSG rule attached to nothing, a
    # storage account open to every network but not to anonymous readers -- the
    # rule returns a lower value on that ``RuleResult``. Never a higher one: the
    # class tag is the tuned number (RULE_ENGINE.md section 5), and a rule that
    # could raise it would be retuning itself one finding at a time.
    exploitability: int
    scope: RuleScope = RuleScope.PER_RESOURCE
    applies_to: ClassVar[list[ResourceType]] = []
    remediation: str = ""
    rationale: str = ""
    estimated_effort_minutes: int = 30
    # Data-driven only. No rule ever branches on a framework name.
    compliance_mappings: ClassVar[dict[str, list[str]]] = {}
    # The evidence this rule reads. If any of it could not be relied on, the
    # rule degrades to UNKNOWN rather than evaluating blind.
    #
    # Declared as keys rather than category names so the dependency is exact.
    # A rule that named a whole category lost its verdict whenever any listing
    # in that category failed, including ones it never read -- CloudGuard
    # reporting a gap it had invented, which is the same overclaim as a PASS
    # nobody earned, pointed the other way.
    requires_evidence: ClassVar[tuple[EvidenceKey, ...]] = ()
    # The machine-readable half of ``remediation`` above: what must be true for
    # this finding to be fixed, and the artifacts generated from that.
    #
    # ``None`` means no declaration has been written, which is deliberately
    # distinguishable from a declaration saying no policy can enforce this. The
    # first is work not done; the second is a fact about the check -- whether an
    # administrator has MFA is a directory setting, and no ``policyRule`` can
    # express it.
    remediation_spec: ClassVar[RemediationSpec | None] = None
    # How this rule's findings read once several of them are open at once.
    #
    # ``None`` -- the default -- is one risk per finding. A declaration means
    # they are one risk with many members: the findings stay per resource,
    # because each is separately fixed and separately verified, while the risk
    # layer stops repeating one sentence and stops charging the security score
    # once per repetition.
    risk_grouping: ClassVar[RiskGrouping | None] = None

    def effective_exploitability(self, result: RuleResult) -> int:
        """What the risk formula should use for this finding.

        The rule's own tag unless the result stepped down from it, and never
        outside 0..tag -- so a mistaken override can only ever understate, which
        is the direction that costs a customer nothing they were not already
        told about by the severity.
        """
        if result.exploitability is None:
            return self.exploitability
        return max(0, min(self.exploitability, result.exploitability))

    @abstractmethod
    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        """Return the rule's verdict. Must be pure and deterministic."""

    def matches(self, resource: CloudResource) -> bool:
        """Whether this rule has anything to say about this resource.

        The provider check is not redundant with the type check. Resource types
        are cloud-neutral by design -- an S3 bucket and an Azure storage account
        both normalize to ``STORAGE_ACCOUNT`` -- so type alone would let an
        Azure rule evaluate an AWS bucket and raise a finding carrying
        ``az storage account update`` as the fix for it.

        Harmless while Azure is the only provider, which is exactly why it is
        worth fixing now: the day a second connector lands, this is a silent
        wrong answer rather than a crash.
        """
        return (
            resource.provider == self.provider
            and resource.resource_type in self.applies_to
        )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{type(self).__name__} {self.rule_id} v{self.version}>"
