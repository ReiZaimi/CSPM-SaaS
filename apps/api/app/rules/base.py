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

from app.core.enums import Provider, ResourceType, RuleScope, RuleState, Severity
from app.domain.resource import CloudResource


@dataclass(frozen=True)
class RuleResult:
    state: RuleState
    evidence: dict[str, Any] | None = None
    message: str | None = None
    # Required when an AGGREGATE rule emits several results, so each one can be
    # attributed to the resource it concerns.
    resource_id: str | None = None

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
    # Collection categories that failed this scan, e.g. {"storage": "timeout"}.
    # Rules whose data is missing degrade to UNKNOWN instead of guessing.
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

    def has_collection_error(self, *categories: str) -> str | None:
        for category in categories:
            if category in self.collection_errors:
                return self.collection_errors[category]
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
    # Static 0-5 tag feeding the risk formula (RISK_ENGINE.md section 1).
    exploitability: int = 0
    scope: RuleScope = RuleScope.PER_RESOURCE
    applies_to: ClassVar[list[ResourceType]] = []
    remediation: str = ""
    rationale: str = ""
    estimated_effort_minutes: int = 30
    # Data-driven only. No rule ever branches on a framework name.
    compliance_mappings: ClassVar[dict[str, list[str]]] = {}
    # Collection categories this rule depends on; if one failed, the engine
    # degrades the rule to UNKNOWN rather than letting it evaluate blind.
    requires_collection: ClassVar[list[str]] = []

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
