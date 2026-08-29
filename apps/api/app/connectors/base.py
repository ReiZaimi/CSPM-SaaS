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

from app.core.enums import Provider, RelationshipType
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
    version: str = "1.0"
    # category -> provider payload, e.g. {"network_security_groups": [...]}
    data: dict[str, Any] = field(default_factory=dict)
    # category -> error message. A storage timeout must not fail the whole scan;
    # it degrades that category's rules to UNKNOWN (AZURE_INTEGRATION.md section 5).
    errors: dict[str, str] = field(default_factory=dict)
    # Per-task outcome from the collection run: what was read completely, what
    # came back partial, what failed, what was skipped. ``errors`` above is
    # derived from this and drives rule degradation; this is the detail behind
    # it, kept so a scan can explain *which* listing was short rather than only
    # that the category is unreliable.
    coverage: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "provider": self.provider.value,
            "tenant_id": self.tenant_id,
            "subscription_id": self.subscription_id,
            "version": self.version,
            "data": self.data,
            "errors": self.errors,
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
            version=payload.get("version", "1.0"),
            data=dict(payload.get("data") or {}),
            errors=dict(payload.get("errors") or {}),
            # Absent on snapshots taken before coverage was recorded. Empty is
            # the honest reading: those runs cannot say what they saw in full,
            # and inventing a COMPLETE for them would be the exact overclaim
            # the field was added to prevent.
            coverage=dict(payload.get("coverage") or {}),
        )


@dataclass
class NormalizedState:
    """Provider-neutral state, ready for the rule engine."""

    resources: list[CloudResource] = field(default_factory=list)
    relationships: list[tuple[str, RelationshipType, str]] = field(default_factory=list)
    collection_errors: dict[str, str] = field(default_factory=dict)


class CloudConnector(ABC):
    provider: Provider

    @abstractmethod
    async def validate_connection(self) -> ConnectionCheck:
        """Prove read access works, by actually calling the provider."""

    @abstractmethod
    async def collect(
        self, on_progress: Callable[[int, int], Awaitable[None]] | None = None
    ) -> RawSnapshot:
        """Gather raw provider state. Never evaluates anything.

        ``on_progress`` is called as units of collection finish, with (done,
        total). The total is known before collection starts, which is what lets
        the slowest phase of a scan report something better than a phase name.
        """

    @abstractmethod
    def normalize(self, snapshot: RawSnapshot) -> NormalizedState:
        """Map provider payloads onto cloud-neutral resources. Pure function."""
