"""The cloud-neutral connector contract.

Azure is the only implementation in v0.1, but the seam is real: everything above
this line (rule engine, risk engine, findings, UI) speaks in ``CloudResource``
and never in ARM resource ids or Graph payloads. Adding AWS later means writing
a collector and a normalizer, not reshaping the core (ARCHITECTURE.md section 6).

The pipeline is fixed and each stage is separately testable:

    collect() -> raw snapshot -> normalize() -> CloudResource list -> rules
"""

from abc import ABC, abstractmethod
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

    def to_json(self) -> dict[str, Any]:
        return {
            "provider": self.provider.value,
            "tenant_id": self.tenant_id,
            "subscription_id": self.subscription_id,
            "version": self.version,
            "data": self.data,
            "errors": self.errors,
        }


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
    async def collect(self) -> RawSnapshot:
        """Gather raw provider state. Never evaluates anything."""

    @abstractmethod
    def normalize(self, snapshot: RawSnapshot) -> NormalizedState:
        """Map provider payloads onto cloud-neutral resources. Pure function."""
