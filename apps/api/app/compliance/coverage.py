"""Turning scan results into a per-control verdict.

The interesting decision is what a *green* control means, and this module takes
the same position the rest of CloudGuard does: UNKNOWN is never PASS
(``rules/base.py``). A control whose rules could not be evaluated is
INCONCLUSIVE, not compliant. Reporting "your storage controls are met" because
the storage API timed out is exactly the failure the coverage ledger exists to
prevent -- and in a compliance view it is the version of that failure someone
might put in front of an auditor.

Pure functions only. Nothing here touches the database, so the precedence rules
below can be tested directly rather than through a scan.
"""

from dataclasses import dataclass
from enum import StrEnum


class ControlStatus(StrEnum):
    """What CloudGuard can say about one control, in order of precedence."""

    # At least one mapped rule is currently failing.
    FAILING = "FAILING"
    # Nothing failing, but a mapped rule could not be evaluated. Not a pass.
    INCONCLUSIVE = "INCONCLUSIVE"
    # Every mapped rule was evaluated conclusively and none is failing.
    PASSING = "PASSING"
    # Rules map to this control, but no scan has produced a result yet.
    NOT_ASSESSED = "NOT_ASSESSED"
    # No rule maps here. CloudGuard has nothing to say -- and says so.
    NOT_COVERED = "NOT_COVERED"


# Statuses that count toward "controls CloudGuard can currently speak to".
CONCLUSIVE_STATUSES = frozenset({ControlStatus.FAILING, ControlStatus.PASSING})


@dataclass(frozen=True)
class RuleEvidence:
    """One rule's contribution to a control, from the latest scan."""

    rule_id: str
    name: str
    severity: str
    open_finding_count: int
    unknown_count: int
    evaluated: bool


def resolve_control_status(
    evidence: list[RuleEvidence], *, has_completed_scan: bool
) -> ControlStatus:
    """Precedence: failing beats inconclusive beats passing.

    A single failing rule makes the whole control failing even if four others
    pass -- controls are met or not met, and partial credit would let a real
    misconfiguration hide behind its neighbours.
    """
    if not evidence:
        return ControlStatus.NOT_COVERED
    if not has_completed_scan or not any(e.evaluated for e in evidence):
        return ControlStatus.NOT_ASSESSED
    if any(e.open_finding_count > 0 for e in evidence):
        return ControlStatus.FAILING
    # Either a rule returned UNKNOWN, or it never ran in the latest scan. Both
    # mean the same thing here: we did not look, so we cannot claim it is fine.
    if any(e.unknown_count > 0 or not e.evaluated for e in evidence):
        return ControlStatus.INCONCLUSIVE
    return ControlStatus.PASSING


def coverage_ratio(statuses: list[ControlStatus]) -> float | None:
    """Share of catalogued controls CloudGuard reached a conclusion on.

    Deliberately not "share passing" -- that would be a compliance score, and
    this product does not issue those. It answers a narrower question: how much
    of this framework can CloudGuard currently speak to at all?
    """
    if not statuses:
        return None
    conclusive = sum(1 for s in statuses if s in CONCLUSIVE_STATUSES)
    return round(conclusive / len(statuses), 4)


def status_counts(statuses: list[ControlStatus]) -> dict[str, int]:
    """Every status present as a key, including zeroes -- a UI that renders a
    legend needs the absent ones too."""
    counts = {status.value: 0 for status in ControlStatus}
    for status in statuses:
        counts[status.value] += 1
    return counts
