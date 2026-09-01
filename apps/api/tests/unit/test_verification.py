"""What CloudGuard is allowed to say about a fix somebody claims to have made.

"Verified fixed" is the strongest sentence this product produces, so the policy
that decides when it may be said is worth testing on its own, without a database
or a scan in the way. The cases divide into two halves and both are about
honesty rather than mechanics:

* An early FAIL is not a failed fix. A cloud applies a change to its control
  plane before every read path agrees about it, so a check run a minute after
  the work reports the environment as it was -- and reporting *that* as "still
  failing" is how a verification feature teaches its customers not to believe
  it.
* Failing to look is not looking and disagreeing. STILL_FAILING and
  INSUFFICIENT_EVIDENCE are different news for different people, and collapsing
  them is the same overclaim as counting an UNKNOWN as a PASS.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.core.enums import RuleState, VerificationStatus
from app.models.verification import RemediationVerification
from app.services.verification import (
    ATTEMPT_SCHEDULE,
    next_attempt_after,
    observe,
)

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
SCAN = uuid4()


def claimed(*, at: datetime = NOW) -> RemediationVerification:
    return RemediationVerification(
        organization_id=uuid4(),
        finding_id=uuid4(),
        rule_id="AZ-STO-001",
        resource_id=uuid4(),
        status=VerificationStatus.PENDING,
        claimed_at=at,
        attempts=0,
        observed_failure=False,
        next_attempt_at=next_attempt_after(0, now=at),
    )


def run(states: list[RuleState], *, start: datetime = NOW) -> RemediationVerification:
    """Observe a sequence of verdicts, one per attempt, walking the schedule."""
    verification = claimed(at=start)
    moment = start
    for state in states:
        moment = verification.next_attempt_at or moment
        observe(verification, state, scan_id=SCAN, now=moment)
    return verification


# ---------------------------------------------------------------- the good case
def test_a_pass_verifies_the_fix_on_the_first_look() -> None:
    verification = run([RuleState.PASS])

    assert verification.status is VerificationStatus.VERIFIED
    assert verification.verified_by_scan_id == SCAN
    assert verification.settled_at is not None
    # Nothing left to do, so nothing left to schedule. A settled verification
    # with a next attempt would have the scheduler starting scans to answer a
    # question that is already answered.
    assert verification.next_attempt_at is None


def test_a_rule_that_no_longer_applies_counts_as_fixed() -> None:
    """The asset is no longer the kind of thing the rule judges.

    A public database made private is not "the check stopped applying" as a
    technicality -- it is the fix, expressed as a reconfiguration rather than a
    setting.
    """
    verification = run([RuleState.NOT_APPLICABLE])
    assert verification.status is VerificationStatus.VERIFIED


def test_a_pass_after_earlier_failures_still_verifies() -> None:
    """The case the backoff exists for: the change had not propagated yet."""
    verification = run([RuleState.FAIL, RuleState.FAIL, RuleState.PASS])

    assert verification.status is VerificationStatus.VERIFIED
    assert verification.attempts == 3


# ------------------------------------------------------------------ the backoff
def test_an_early_failure_is_not_reported_as_a_failed_fix() -> None:
    verification = run([RuleState.FAIL])

    assert verification.status is VerificationStatus.PENDING
    assert verification.next_attempt_at is not None
    assert "look again" in (verification.detail or "")


def test_each_attempt_waits_longer_than_the_last() -> None:
    verification = claimed()
    gaps = []
    moment = NOW
    for _ in ATTEMPT_SCHEDULE[:-1]:
        previous = verification.next_attempt_at
        assert previous is not None
        moment = previous
        observe(verification, RuleState.FAIL, scan_id=SCAN, now=moment)
        assert verification.next_attempt_at is not None
        gaps.append(verification.next_attempt_at - moment)

    assert gaps == sorted(gaps), "the backoff must widen, not repeat"
    assert gaps[0] >= timedelta(minutes=5)


def test_the_attempts_run_out_rather_than_retrying_for_ever() -> None:
    """An answer is the product. A verification that never settles is the same
    silence this whole mechanism was built to remove, dressed as diligence."""
    verification = run([RuleState.FAIL] * len(ATTEMPT_SCHEDULE))

    assert verification.status is VerificationStatus.STILL_FAILING
    assert verification.next_attempt_at is None
    assert verification.attempts == len(ATTEMPT_SCHEDULE)


# ----------------------------------------------- looking versus failing to look
def test_never_being_able_to_look_is_insufficient_evidence() -> None:
    """CloudGuard's problem to explain, not the customer's to fix.

    Telling somebody who has done the work that their fix failed, when in truth
    the evidence never arrived, is the same overclaim as a PASS nobody earned --
    pointed at the person rather than at the environment.
    """
    verification = run([RuleState.UNKNOWN] * len(ATTEMPT_SCHEDULE))

    assert verification.status is VerificationStatus.INSUFFICIENT_EVIDENCE
    assert "could not gather the evidence" in (verification.detail or "")
    assert "failed fix" in (verification.detail or "")


def test_one_definite_failure_outweighs_later_blindness() -> None:
    """Having seen the check fail is a stronger, truer statement than "we could
    not tell", so a run of UNKNOWNs afterwards still settles as still failing."""
    verification = run(
        [RuleState.FAIL] + [RuleState.UNKNOWN] * (len(ATTEMPT_SCHEDULE) - 1)
    )

    assert verification.status is VerificationStatus.STILL_FAILING
    assert verification.observed_failure is True


def test_an_unknown_before_the_attempts_run_out_says_so_plainly() -> None:
    verification = run([RuleState.UNKNOWN])

    assert verification.status is VerificationStatus.PENDING
    assert "could not read enough" in (verification.detail or "")


def test_the_last_state_is_recorded_for_every_attempt() -> None:
    verification = run([RuleState.FAIL, RuleState.UNKNOWN])

    assert verification.last_state is RuleState.UNKNOWN
    assert verification.attempts == 2
    assert verification.last_attempt_at is not None


def test_a_settled_verification_names_how_long_it_was_checked() -> None:
    verification = run([RuleState.FAIL] * len(ATTEMPT_SCHEDULE))

    detail = verification.detail or ""
    assert f"Checked {len(ATTEMPT_SCHEDULE)} times" in detail
    assert "hours" in detail or "an hour" in detail


def test_the_schedule_ends_rather_than_wrapping() -> None:
    assert next_attempt_after(0, now=NOW) == NOW + ATTEMPT_SCHEDULE[0]
    assert next_attempt_after(len(ATTEMPT_SCHEDULE), now=NOW) is None
    assert next_attempt_after(len(ATTEMPT_SCHEDULE) + 5, now=NOW) is None
