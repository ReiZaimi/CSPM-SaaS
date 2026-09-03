"""Why a control is inconclusive, not merely that it is.

INCONCLUSIVE is the one verdict on a compliance control a reader cannot act on
from the verdict alone. FAILING points at findings. PASSING needs nothing.
NOT_COVERED is a fact about CloudGuard rather than about the customer. "Three
rules could not be evaluated" points nowhere -- and the sentence that answers it
has been sitting in ``scan_evaluation_gaps`` since UNKNOWN became a recorded
outcome, never read by this view.

It matters more since the scanner role started gaining permissions, because the
answer is frequently "your deployed role predates the permission this needs",
which is a thing a customer can act on this afternoon.
"""

from app.compliance.coverage import (
    ControlStatus,
    RuleEvidence,
    resolve_control_status,
)

ROLE_REASON = (
    "The server's auditing settings could not be read. If this persists, the "
    "deployed scanner role may predate the permission that reads them."
)


def evidence(**overrides: object) -> RuleEvidence:
    base: dict = {
        "rule_id": "AZ-DB-003",
        "name": "Database server keeps no audit trail",
        "severity": "MEDIUM",
        "open_finding_count": 0,
        "unknown_count": 0,
        "evaluated": True,
        "unknown_reasons": (),
    }
    base.update(overrides)
    return RuleEvidence(**base)  # type: ignore[arg-type]


class TestReasonsTravelWithTheVerdict:
    def test_an_inconclusive_control_can_carry_its_reason(self) -> None:
        rule = evidence(unknown_count=4, unknown_reasons=(ROLE_REASON,))

        status = resolve_control_status([rule], has_completed_scan=True)

        assert status == ControlStatus.INCONCLUSIVE
        assert rule.unknown_reasons == (ROLE_REASON,)

    def test_a_rule_that_told_us_something_carries_no_reason(self) -> None:
        """A default of "no explanation" rather than an empty string, so a
        consumer can distinguish "nothing went wrong" from "something did and
        nobody wrote it down"."""
        assert evidence().unknown_reasons == ()

    def test_several_reasons_are_kept_apart(self) -> None:
        """One rule can fail differently on different resources: a storage
        account whose listing timed out and another whose configuration never
        arrived are two causes, and collapsing them would name the wrong one
        for half the assets."""
        rule = evidence(
            unknown_count=2,
            unknown_reasons=("Azure timed out", "Configuration missing from snapshot"),
        )

        assert len(rule.unknown_reasons) == 2


class TestTheVerdictItselfIsUnchanged:
    """The reasons are carried beside the precedence rules, never into them."""

    def test_a_failing_rule_still_outranks_an_inconclusive_one(self) -> None:
        status = resolve_control_status(
            [
                evidence(open_finding_count=1),
                evidence(rule_id="AZ-DB-001", unknown_count=3, unknown_reasons=("x",)),
            ],
            has_completed_scan=True,
        )

        assert status == ControlStatus.FAILING

    def test_an_explained_unknown_is_still_not_a_pass(self) -> None:
        """The whole point of the coverage ledger. Knowing why CloudGuard could
        not look is not the same as having looked, and an explanation must
        never soften the verdict."""
        status = resolve_control_status(
            [evidence(unknown_count=1, unknown_reasons=(ROLE_REASON,))],
            has_completed_scan=True,
        )

        assert status == ControlStatus.INCONCLUSIVE

    def test_a_control_no_rule_maps_to_is_still_not_covered(self) -> None:
        """Different from inconclusive, and the page renders them differently:
        one is CloudGuard having nothing to say, the other is CloudGuard having
        looked and failed."""
        assert (
            resolve_control_status([], has_completed_scan=True)
            == ControlStatus.NOT_COVERED
        )
