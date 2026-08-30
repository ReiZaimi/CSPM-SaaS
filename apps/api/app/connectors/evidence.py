"""What a rule needs, named in a way that cannot silently stop matching.

A rule declares the evidence it depends on and the engine degrades it to UNKNOWN
when that evidence did not arrive. Until now both halves of that were bare
strings -- ``requires_collection = ["identity"]`` on one side, ``category=
"identity"`` on a collection task on the other -- with nothing checking that the
two ever met. A typo did not fail: it produced a rule that never degraded,
which is the one failure mode this whole mechanism exists to prevent. There was
already one in the tree, ``has_collection_error("identity", "mfa")``, where no
task has ever produced ``mfa``.

Two levels, because two different questions are being asked.

**Evidence keys** name one unit of collection -- one listing, one query. This is
what a rule should depend on, because it is the finest thing that can fail on
its own: a subscription whose PostgreSQL listing failed has still read its SQL
servers perfectly well, and the SQL rule has no business going UNKNOWN over it.
Keys are provider-specific, so they live beside the provider that produces them.

**Evidence categories** group keys into the buckets that share a permission and
an explanation. This is what the customer's role grants, what the scan banner
reports, and what a stale role deployment degrades. Categories are neutral: an
AWS network listing and an Azure one are both NETWORK.

The mapping between the two lives with the keys, so a task never declares its
own category and the two can never disagree.
"""

from enum import StrEnum


class EvidenceCategory(StrEnum):
    """The bucket a piece of evidence belongs to.

    Provider-neutral on purpose. These are the divisions a cloud's read
    permissions actually fall along, and every provider has the same ones --
    which is why the customer-facing explanation of a missing permission can be
    written once.
    """

    RESOURCES = "resources"
    NETWORK = "network"
    COMPUTE = "compute"
    STORAGE = "storage"
    DATABASE = "database"
    LOGGING = "logging"
    IDENTITY = "identity"


class EvidenceKey(StrEnum):
    """Base for a provider's evidence keys. Deliberately holds no members.

    An enum with members cannot be subclassed, which is exactly the property
    wanted here: this class exists so the provider-neutral collection executor
    can be typed against "an evidence key" while each provider supplies its own,
    and nothing can add a member to the shared base by accident.

    Subclasses must override :attr:`category`. The base raising rather than
    guessing is the point -- an unmapped key must fail loudly at the provider
    that forgot it, not degrade a rule for a reason nobody chose.
    """

    @property
    def category(self) -> EvidenceCategory:
        raise NotImplementedError(
            f"{type(self).__name__} does not map {self.value} to a category"
        )
