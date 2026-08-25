"""The evaluation-time view of a cloud asset.

Deliberately a plain, immutable dataclass with no database and no provider SDK
behind it. Two consequences that matter:

* Rules can be unit-tested against fixture JSON with no PostgreSQL, no Azure and
  no network -- which is the whole testing strategy (TESTING.md section 1).
* Nothing Azure-specific reaches rule code. An AWS normalizer would emit these
  same objects, so the rule engine never learns what cloud it is looking at.
"""

from dataclasses import dataclass, field
from typing import Any

from app.core.enums import Level, Provider, ResourceType


@dataclass(frozen=True)
class CloudResource:
    provider_resource_id: str
    resource_type: ResourceType
    name: str
    provider: Provider = Provider.AZURE
    region: str | None = None
    environment: str | None = None
    criticality: Level = Level.UNKNOWN
    data_sensitivity: Level = Level.UNKNOWN
    public_exposure: Level = Level.UNKNOWN
    metadata: dict[str, Any] = field(default_factory=dict)

    def get(self, path: str, default: Any = None) -> Any:
        """Read a dotted path out of ``metadata``.

        Returns ``default`` for anything missing, which lets a rule distinguish
        "the value is absent" from "the value is False" -- the difference
        between UNKNOWN and PASS.
        """
        node: Any = self.metadata
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node
