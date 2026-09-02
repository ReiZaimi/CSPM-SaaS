"""When several findings are one problem.

A rule that runs over every member of a set reports one failure per member,
which is right: each account, each storage container, is a separate thing
somebody has to go and fix, with its own history and its own verification. It
is wrong at the layer above. Forty privileged accounts with no second factor is
one sentence, one decision and one Conditional Access policy -- and as forty
risks it is forty rows saying the same thing, and forty Critical deductions,
which pins the org security score at zero on the strength of a single
misconfiguration repeated.

So the finding stays per resource and the *risk* groups. ``risk_findings`` has
been a junction since the schema was written precisely so this would be a
service-layer change rather than a migration (RISK_ENGINE.md section 2).

A rule opts in by declaring one of these. Declared rather than inferred: whether
a set of failures is one problem or many is a judgement about the rule's
subject, not a property of the count. Two storage accounts left public are two
mistakes made twice; two administrators without MFA are one policy that was
never written.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskGrouping:
    """How a rule's findings read once they are counted rather than listed.

    Two sentences rather than one with a plural suffix, because the singular is
    not the plural with an "s": "1 privileged accounts without multi-factor
    authentication" is the kind of text that tells a customer nobody read this
    screen.
    """

    #: Shown when exactly one finding is open. No placeholder.
    singular: str
    #: Shown otherwise. Formatted with ``count``.
    plural: str

    def title(self, count: int) -> str:
        return self.singular if count == 1 else self.plural.format(count=count)
