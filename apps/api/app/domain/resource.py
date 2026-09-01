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

from app.core.enums import ContextSource, Level, Provider, ResourceType


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
    # Where each context value came from -- a tag, a guess at the name, the kind
    # of thing this is, or a person at the customer saying so. Carried beside
    # the value rather than derived later because by the time a score exists the
    # inputs are indistinguishable: a CRITICAL somebody typed into a tag and a
    # CRITICAL guessed from a resource name multiply a finding identically, and
    # only one of them is worth arguing with.
    #
    # ``public_exposure`` has no source, and that is not an omission: it is read
    # off the configuration in the capture -- a public IP is attached or it is
    # not -- so there is nothing to attribute and nothing for a customer to
    # declare.
    criticality_source: ContextSource = ContextSource.NONE
    data_sensitivity_source: ContextSource = ContextSource.NONE
    environment_source: ContextSource = ContextSource.NONE
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
