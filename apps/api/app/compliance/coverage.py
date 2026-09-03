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

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
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
    # Why the rule could not tell, in the words the rule itself used. Empty
    # unless something went unevaluated.
    #
    # A control resolving to INCONCLUSIVE is the one verdict a customer cannot
    # act on from the verdict alone: FAILING points at findings, PASSING needs
    # nothing, NOT_COVERED is a fact about CloudGuard. "Three could not be
    # evaluated" points nowhere -- and since the scanner role gained
    # permissions, the answer is frequently "redeploy the role", which is a
    # thing they can do this afternoon.
    #
    # A tuple because one rule can fail differently on different resources: a
    # storage account whose listing timed out and another whose configuration
    # never arrived are two reasons, and collapsing them to one would name the
    # wrong cause for half the assets.
    unknown_reasons: tuple[str, ...] = ()


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


# Which outcome wins when one reading was taken across several subscriptions.
# Worst first, and for the reason the rule engine gives about PARTIAL: a listing
# known to be incomplete cannot support "none of them are public", so a control
# whose storage listing was truncated in one subscription out of nine has to say
# so rather than average it away.
_OUTCOME_RANK = {"FAILED": 3, "PARTIAL": 2, "COMPLETE": 1}


@dataclass(frozen=True)
class Reading:
    """One provider listing behind a control, as the latest scan took it.

    Aggregated across scopes rather than one entry per subscription: a tenant of
    fifty subscriptions read storage fifty times, and fifty identical rows under
    one control is a table nobody reads. What survives aggregation is what an
    auditor asks about -- the worst outcome, the oldest read, how many scopes it
    covered, the permission it was made under, and whether the bytes are still
    there to check.
    """

    evidence_key: str
    # None where the latest scan holds no reading of this key at all. That is
    # not the same as a failed read and must not render as one: the first says
    # nothing was collected, the second says the provider refused. Both stop a
    # control being green on nothing, which is why neither is dropped.
    outcome: str | None
    scopes: int
    # The *oldest* of the readings, not the newest. A control is only as current
    # as the least current thing it rests on, and taking the newest would let
    # forty-nine fresh subscriptions hide the one that has not been read since
    # Tuesday.
    collected_at: datetime | None
    permissions: tuple[str, ...] = ()
    # Whether every payload behind this reading is still stored. Retention
    # prunes bytes long before it prunes the record that they were read
    # (DECISIONS.md §51), so a citation can be true and no longer followable --
    # and saying which is the difference between provenance and a dead link.
    retained: bool = False


def summarize_readings(
    keys: Iterable[str],
    rows: Sequence[tuple[str, str, datetime, Sequence[str], str | None]],
    stored_hashes: frozenset[str] = frozenset(),
) -> tuple[Reading, ...]:
    """Fold this scan's readings into one entry per declared key.

    ``rows`` are ``(evidence_key, outcome, collected_at, permissions,
    content_hash)`` as the evidence table holds them, one per scope. ``keys`` is
    what the control's rules declared they read -- passed separately because a
    key with no row is the case that matters most: it means the verdict above it
    rests on a reading nobody took.
    """
    by_key: dict[str, list[tuple[str, datetime, Sequence[str], str | None]]] = {}
    for evidence_key, outcome, collected_at, permissions, content_hash in rows:
        by_key.setdefault(evidence_key, []).append(
            (outcome, collected_at, permissions, content_hash)
        )

    readings: list[Reading] = []
    for key in sorted(set(keys)):
        entries = by_key.get(key, [])
        if not entries:
            readings.append(Reading(evidence_key=key, outcome=None, scopes=0, collected_at=None))
            continue
        permissions = sorted(
            {permission for _o, _c, perms, _h in entries for permission in perms}
        )
        hashes = [content_hash for _o, _c, _p, content_hash in entries]
        readings.append(
            Reading(
                evidence_key=key,
                outcome=max(
                    (outcome for outcome, _c, _p, _h in entries),
                    key=lambda outcome: _OUTCOME_RANK.get(outcome, 0),
                ),
                scopes=len(entries),
                collected_at=min(collected_at for _o, collected_at, _p, _h in entries),
                permissions=tuple(permissions),
                # Every payload, not any: a control resting on nine readings of
                # which one has been pruned cannot be followed all the way back,
                # and "partly retained" is the honest answer to give as False.
                retained=bool(hashes)
                and all(h is not None and h in stored_hashes for h in hashes),
            )
        )
    return tuple(readings)
