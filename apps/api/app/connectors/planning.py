"""What a scan is going to collect, decided before it collects anything.

Until now a collection plan was a list: eleven tasks for a subscription, three
for the directory, run in full every time whatever the scan was for and whatever
CloudGuard already held. Nothing wrong with the list -- every entry earned its
place -- but nothing derived it either, so two questions had no answer.

**Does anything use this?** A listing is collected because a rule reads it or
because the product needs it (inventory, the graph's identity edges). Both are
declared -- ``requires_evidence`` on one side, :meth:`CloudConnector
.baseline_evidence` on the other -- and until they were unioned and compared
against the plan, a task could go on being collected long after the last rule
that read it was deleted, at the customer's expense and nobody's notice.

**Do we need to read it again?** Evidence carries provenance and a hash, so a
reading from an earlier scan is reusable in principle. In practice almost none
of it should be, and that is a product decision rather than a limitation: a
customer who fixes a storage account and asks CloudGuard to check gets an
answer about the storage account as it is *now*, or the word "verified" means
nothing. Reuse is therefore opt-in per evidence key, off by default, and
allowed only where a stale reading cannot change a verdict. See
:attr:`EvidenceKey.reuse_window`.

A plan is a filter over the tasks a provider offers, never a source of them.
The provider still declares how each key is collected and what it depends on;
the plan says which of those to run and which to carry forward. That direction
matters: a plan naming a key the provider does not produce is a plan asking for
nothing, not a plan inventing a collection task.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.connectors.evidence import EvidenceKey


@dataclass(frozen=True)
class CarriedReading:
    """A complete reading from an earlier scan, reused rather than re-read.

    Holds the payload as it was collected and the moment it was collected, and
    the second is the load-bearing half: an evidence row for a carried reading
    records the original ``collected_at``, so the freshness question stays
    answerable and a carried reading can never masquerade as one taken now.
    """

    key: EvidenceKey
    payload: dict[str, Any]
    collected_at: datetime
    item_count: int = 0
    permissions: tuple[str, ...] = ()


@dataclass(frozen=True)
class CollectionPlan:
    """Which evidence to read now, and which to carry forward.

    Scoped to one run: an account plan and a directory plan are planned
    separately because they read different things and their evidence expires
    against different scopes.
    """

    # Every key this run should read from the provider. Keys the provider does
    # not offer are ignored rather than refused -- the requirement set spans
    # every scope a scan covers, and the account plan holding no directory
    # tasks is not a mistake to report.
    collect: frozenset[EvidenceKey] = frozenset()
    carried: Mapping[EvidenceKey, CarriedReading] = field(default_factory=dict)

    def wants(self, key: EvidenceKey) -> bool:
        """Whether this run reads the provider for this key.

        Carried wins over collected wherever both are somehow claimed. One
        method rather than two conditions at the call site, so a reading can
        never be both carried forward and taken again -- which would put two
        results under one key and leave the later one silently winning.
        """
        return key in self.collect and key not in self.carried

    def carried_for(self, key: EvidenceKey) -> CarriedReading | None:
        return self.carried.get(key)

    def restrict(self, keys: Iterable[EvidenceKey]) -> "CollectionPlan":
        """The same plan seen through what one provider plan can produce."""
        offered = frozenset(keys)
        return CollectionPlan(
            collect=self.collect & offered,
            carried={k: v for k, v in self.carried.items() if k in offered},
        )
