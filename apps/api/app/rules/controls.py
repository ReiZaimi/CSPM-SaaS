"""A control standing between an attacker and a finding.

A finding says a thing is misconfigured. A compensating control says something
else in the environment makes exploiting it harder, without making it right --
an account with no registered second factor is still an account with no second
factor, and a Conditional Access policy demanding one is what stops the stolen
password working *today*.

Three rules, and each of them is the product refusing a temptation:

**A control never turns FAIL into PASS.** It cannot: the misconfiguration is
still there, and the control can be disabled, scoped away, or have the affected
principal excluded from it, in a change nobody reviews. Reporting a pass would
be CloudGuard vouching for a state of affairs it is not observing, which is the
same overclaim as a PASS over evidence that never arrived.

**Only prevention counts.** Detection is not compensation. Microsoft Defender
watching a storage account changes whether somebody finds out, not what an
attacker must have to get in -- and the exploitability scale is written in terms
of the second (``RULE_ENGINE.md`` section 5). A control that would only shorten
the time to discovery belongs in a report, not in this number.

**The control must be observed, not assumed.** Every one of these is built from
evidence in the same capture the finding came from, and a control CloudGuard
could not read is simply absent -- the finding keeps its full score. Absence of
evidence lowers nothing, in the direction that is safe to be wrong in.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Control:
    """One observed defence, and what it leaves an attacker needing.

    ``exploitability`` is on the same 0-5 scale as the rule tag it moderates
    (``RULE_ENGINE.md`` section 5) and is applied as a *ceiling*: the finding
    takes the lower of its own value and this one. A control can therefore only
    ever reduce, and several controls compose to the strongest of them without
    any of them having to know about the others.
    """

    #: Stable identifier, provider-namespaced: ``entra.security_defaults``.
    id: str
    #: What it is called where the customer would go and look at it.
    name: str
    #: Why it applies to *this* finding, in a sentence somebody can check.
    detail: str
    #: What an attacker still needs while this control stands.
    exploitability: int

    def as_evidence(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "detail": self.detail,
            "exploitability": self.exploitability,
        }
