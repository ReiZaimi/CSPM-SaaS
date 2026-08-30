"""The cloud-neutral connector contract.

Azure is the only implementation in v0.1, but the seam is real: everything above
this line (rule engine, risk engine, findings, UI) speaks in ``CloudResource``
and never in ARM resource ids or Graph payloads. Adding AWS later means writing
a collector and a normalizer, not reshaping the core (ARCHITECTURE.md section 6).

The pipeline is fixed and each stage is separately testable:

    collect() -> raw snapshot -> normalize() -> CloudResource list -> rules
"""

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from app.connectors.evidence import EvidenceKey
from app.connectors.planning import CollectionPlan
from app.core.enums import CollectionScope, Provider, RelationshipType, TaskOutcome
from app.domain.resource import CloudResource


@dataclass
class ConnectionCheck:
    """Result of verifying we can actually read a customer environment."""

    ok: bool
    tenant_id: str | None = None
    subscription_id: str | None = None
    detail: str = ""
    permissions_verified: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    # Things that will cost the customer a collection category but not the
    # connection. Separate from ``problems`` because ``ok`` is derived from
    # that list, and a connection that can still scan eleven of its twelve
    # tasks is not a broken connection -- calling it one would send someone to
    # fix an outage they do not have.
    notes: list[str] = field(default_factory=list)


@dataclass
class RawSnapshot:
    """Everything collected, exactly as the provider returned it.

    Stored verbatim in ``cloud_snapshots``. Keeping the provider's own shape
    means a scan can be re-evaluated against improved rules later without
    re-contacting the customer's cloud.
    """

    provider: Provider
    tenant_id: str
    subscription_id: str | None
    # What this capture is a reading of. ACCOUNT snapshots belong to one
    # subscription; a DIRECTORY snapshot belongs to the tenant and is taken once
    # per scan. Stated rather than inferred from ``subscription_id`` being None,
    # because replay has to know which it is holding and an absent id is a
    # weaker signal than a declared scope.
    scope: CollectionScope = CollectionScope.ACCOUNT
    version: str = "1.0"
    # category -> provider payload, e.g. {"network_security_groups": [...]}
    data: dict[str, Any] = field(default_factory=dict)
    # category -> error message. The customer-facing view: what the scan banner
    # shows and what a stale role deployment explains, because a permission is
    # granted per category and never per listing
    # (AZURE_INTEGRATION.md section 5).
    errors: dict[str, str] = field(default_factory=dict)
    # evidence key -> error message. The view the *rules* degrade on, and finer
    # than ``errors`` rather than a copy of it. A subscription whose PostgreSQL
    # listing failed has read its SQL servers perfectly well; degrading the SQL
    # rule over a sibling listing would be a gap CloudGuard invented rather than
    # one it found. Both are derived from the same coverage report, so they
    # cannot disagree about what happened -- only about how finely to say it.
    gaps: dict[str, str] = field(default_factory=dict)
    # Per-task outcome from the collection run: what was read completely, what
    # came back partial, what failed, what was skipped. ``errors`` above is
    # derived from this and drives rule degradation; this is the detail behind
    # it, kept so a scan can explain *which* listing was short rather than only
    # that the category is unreliable.
    coverage: dict[str, Any] = field(default_factory=dict)
    # What each unit of collection produced, kept apart from the merged ``data``
    # above and deliberately **not serialized**.
    #
    # ``data`` is the snapshot -- the whole capture, stored verbatim, which is
    # what replay reads. This is the same content sliced by the unit that
    # produced it, which is what evidence is stored by: one row and one
    # content-addressed payload per reading, so an unchanged listing is kept
    # once rather than once per scan.
    #
    # Absent after :meth:`from_json`, and correctly so. A replay collected
    # nothing, so it has no readings to record -- only the capture it was handed.
    payloads: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)

    def to_json(self) -> dict[str, Any]:
        return {
            "provider": self.provider.value,
            "tenant_id": self.tenant_id,
            "subscription_id": self.subscription_id,
            "scope": self.scope.value,
            "version": self.version,
            "data": self.data,
            "errors": self.errors,
            "gaps": self.gaps,
            "coverage": self.coverage,
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "RawSnapshot":
        """Rebuild a snapshot from its stored form, for replay.

        The inverse of :meth:`to_json`, and the reason storing raw provider
        JSON was worth the disk: a stored snapshot can be fed back through
        ``normalize`` and the rule engine without re-contacting the customer's
        cloud. ``errors`` round-trips too -- a category that failed at
        collection time must keep failing on replay, or a rule that degraded to
        UNKNOWN would silently become a PASS the second time it is evaluated.
        """
        return cls(
            provider=Provider(payload["provider"]),
            tenant_id=payload["tenant_id"],
            subscription_id=payload.get("subscription_id"),
            # Absent on snapshots taken before directory collection was hoisted
            # to the tenant. Every one of those was a subscription capture, so
            # ACCOUNT is not a default here so much as the fact about them.
            scope=CollectionScope(payload.get("scope", CollectionScope.ACCOUNT.value)),
            version=payload.get("version", "1.0"),
            data=dict(payload.get("data") or {}),
            errors=dict(payload.get("errors") or {}),
            # Absent on snapshots taken before rules degraded per evidence key.
            # Derived from ``coverage`` when it is, so an old capture replays
            # with the same gaps it originally had rather than with none.
            gaps=dict(payload.get("gaps") or cls._gaps_from_coverage(payload)),
            # Absent on snapshots taken before coverage was recorded. Empty is
            # the honest reading: those runs cannot say what they saw in full,
            # and inventing a COMPLETE for them would be the exact overclaim
            # the field was added to prevent.
            coverage=dict(payload.get("coverage") or {}),
        )

    @staticmethod
    def _gaps_from_coverage(payload: dict[str, Any]) -> dict[str, str]:
        """Per-key gaps reconstructed from a snapshot that predates them.

        The coverage report already recorded every task's outcome, so an older
        capture carries the facts even though it never carried this shape. A
        replay of one has to degrade exactly the rules the original run degraded
        -- an old snapshot silently replaying with no gaps would turn every
        UNKNOWN it earned into a PASS the second time around, which is the one
        thing replay must never do.
        """
        gaps: dict[str, str] = {}
        for key, entry in (payload.get("coverage") or {}).items():
            outcome = str(entry.get("outcome", ""))
            if outcome and outcome != TaskOutcome.COMPLETE.value:
                gaps[key] = entry.get("detail") or outcome.lower()
        return gaps


@dataclass
class NormalizedState:
    """Provider-neutral state, ready for the rule engine."""

    resources: list[CloudResource] = field(default_factory=list)
    relationships: list[tuple[str, RelationshipType, str]] = field(default_factory=list)
    # Evidence key -> why it cannot be relied on. Carried through to
    # ``RuleContext``, which is where it decides between UNKNOWN and a verdict.
    collection_errors: dict[str, str] = field(default_factory=dict)


class CloudConnector(ABC):
    provider: Provider

    @abstractmethod
    async def validate_connection(self) -> ConnectionCheck:
        """Prove read access works, by actually calling the provider."""

    @staticmethod
    def baseline_evidence() -> frozenset[EvidenceKey]:
        """Evidence this provider collects whatever the rule set asks for.

        The rules declare most of it: a plan derived from ``requires_evidence``
        collects everything some rule reads and nothing else. What that misses
        is the evidence the *product* is built from rather than judged from --
        the asset inventory, the graph's edges -- which no rule names and which
        a rule-derived plan would therefore quietly stop collecting.

        Empty by default, and a provider that forgets to override it does not
        fail quietly: every key its plan produces must be either required by a
        rule or declared here, and a test says so.
        """
        return frozenset()

    @abstractmethod
    async def collect(
        self,
        on_progress: Callable[[int, int], Awaitable[None]] | None = None,
        plan: CollectionPlan | None = None,
    ) -> RawSnapshot:
        """Gather one account's raw state. Never evaluates anything.

        ``on_progress`` is called as units of collection finish, with (done,
        total). The total is known before collection starts, which is what lets
        the slowest phase of a scan report something better than a phase name.

        ``plan`` narrows what is read and supplies what is carried forward from
        earlier scans. ``None`` reads everything the provider offers, which is
        what an unplanned scan has always done and what a scan with nothing
        reusable still does.
        """

    @abstractmethod
    async def collect_directory(
        self,
        on_progress: Callable[[int, int], Awaitable[None]] | None = None,
        plan: CollectionPlan | None = None,
    ) -> RawSnapshot:
        """Gather the trust boundary's own state, once per scan.

        Separate from :meth:`collect` because it is a reading of a different
        thing. Users, groups and directory roles belong to the tenant, not to
        any subscription beneath it, and every cloud has this split -- an AWS
        organization and a GCP organization are the same shape of fact.

        Collecting it inside the per-account plan was not merely wasteful. The
        directory came back once per subscription and normalized into one set
        of user resources per subscription, so a tenant of twenty subscriptions
        held twenty rows for every administrator and raised twenty findings for
        each one that lacked MFA.
        """

    @abstractmethod
    def normalize(self, snapshot: RawSnapshot) -> NormalizedState:
        """Map provider payloads onto cloud-neutral resources. Pure function."""
