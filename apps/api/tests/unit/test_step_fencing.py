"""What stops two workers running one step, and one worker settling another's.

A scan runs as leased steps: a worker claims one, renews while it works, and
settles it at the end. The lease is what makes a redeploy survivable -- an
expired one returns the step to PENDING and another worker picks it up.

The half that was missing is what happens when the first worker comes back. A
process paused past its lease -- a throttled container, a database stall, a
long stop-the-world -- has not died, and it finished its collection minutes
later and marked the step SUCCEEDED while another worker was in the middle of
the same step. ANALYZE waits on collection *settling*, so the scan then
interpreted a subscription that was still being written, and reported the
result as a complete reading.

So the claim's attempt number is a fence. Every write a running step makes --
its renewals and its settle -- is conditional on the row still carrying the
attempt it was claimed under, and a worker that lost the step writes nothing.
"""

import uuid

import pytest

from app.core.enums import ScanStepKind, ScanStepStatus
from app.models.scan import ScanStep
from app.services import orchestrator
from app.services.scanner import LeaseKeeper, StepLeaseLost, _StepHeartbeat


class Result:
    def __init__(self, rowcount: int) -> None:
        self.rowcount = rowcount


class FencedSession:
    """A session that reports whether a guarded UPDATE matched anything.

    The guard is the whole subject here, so the fake answers on the same terms
    PostgreSQL does: a row count, not an exception.
    """

    def __init__(self, *, matched: bool = True) -> None:
        self.matched = matched
        self.statements: list[str] = []
        self.commits = 0

    async def execute(self, statement: object) -> Result:
        self.statements.append(str(statement))
        return Result(1 if self.matched else 0)

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, _row: object) -> None:
        return None


def step(attempt: int = 1) -> ScanStep:
    made = ScanStep(
        organization_id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        kind=ScanStepKind.COLLECT,
        status=ScanStepStatus.RUNNING,
        attempt=attempt,
        max_attempts=3,
    )
    made.id = uuid.uuid4()
    return made


# ------------------------------------------------------------------ renewing
async def test_a_renewal_reports_whether_the_step_is_still_ours() -> None:
    session = FencedSession(matched=True)
    assert await orchestrator.renew(session, uuid.uuid4(), attempt=2) is True


async def test_a_renewal_of_a_reclaimed_step_is_refused() -> None:
    """The refusal is the signal. Renewing unconditionally kept the lease of a
    step somebody else was running alive, which hid the one condition the lease
    exists to detect."""
    session = FencedSession(matched=False)
    assert await orchestrator.renew(session, uuid.uuid4(), attempt=2) is False


async def test_a_renewal_is_conditional_on_the_claim_it_was_made_under() -> None:
    session = FencedSession()
    await orchestrator.renew(session, uuid.uuid4(), attempt=2)
    statement = session.statements[0]

    assert "scan_steps.status" in statement
    assert "scan_steps.attempt" in statement


# ------------------------------------------------------------------ settling
async def test_a_settle_lands_while_the_step_is_still_ours() -> None:
    session = FencedSession(matched=True)
    settled = await orchestrator.finish(
        session, step(), ScanStepStatus.SUCCEEDED, attempt=1
    )
    assert settled is True


async def test_a_settle_is_refused_once_the_step_has_been_reclaimed() -> None:
    """The case that corrupted a scan: a slow worker returning to mark SUCCEEDED
    a step another worker had already been given."""
    session = FencedSession(matched=False)
    settled = await orchestrator.finish(
        session, step(), ScanStepStatus.SUCCEEDED, attempt=1
    )
    assert settled is False


async def test_an_unfenced_settle_still_works_for_the_reaper() -> None:
    """The reaper settles steps it did not run, and owns them by their expiry
    rather than by a claim. It passes no attempt, and must not be refused."""
    session = FencedSession(matched=False)
    settled = await orchestrator.finish(session, step(), ScanStepStatus.FAILED)
    assert settled is True


async def test_a_retry_of_a_reclaimed_step_decides_nothing() -> None:
    """None rather than PENDING, and the difference matters: a late failure that
    put the step back would spend an attempt on the run that replaced it."""
    session = FencedSession(matched=False)
    outcome = await orchestrator.fail_or_retry(
        session, step(attempt=1), "timed out", attempt=1
    )
    assert outcome is None


async def test_a_retry_within_the_claim_returns_the_step_to_the_queue() -> None:
    session = FencedSession(matched=True)
    outcome = await orchestrator.fail_or_retry(
        session, step(attempt=1), "timed out", attempt=1
    )
    assert outcome == ScanStepStatus.PENDING


async def test_the_last_attempt_fails_rather_than_retrying() -> None:
    session = FencedSession(matched=True)
    outcome = await orchestrator.fail_or_retry(
        session, step(attempt=3), "timed out", attempt=3
    )
    assert outcome == ScanStepStatus.FAILED


# ------------------------------------------------------- holding the lease
def test_the_lease_is_renewed_several_times_inside_its_own_window() -> None:
    """Once per window would make a single missed renewal -- a slow query, a
    paused container -- indistinguishable from a dead worker."""
    assert LeaseKeeper.RENEW_EVERY <= ScanStep.LEASE_SECONDS / 3


async def test_a_step_that_lost_its_lease_stops_at_the_next_progress_report() -> None:
    """Every request after that point spends the customer's Azure quota to
    produce a capture another worker is already producing."""
    keeper = LeaseKeeper(uuid.uuid4(), uuid.uuid4(), attempt=1)
    keeper.lost = True

    with pytest.raises(StepLeaseLost):
        await _StepHeartbeat(keeper)(1, 10)


async def test_a_held_lease_lets_collection_carry_on() -> None:
    keeper = LeaseKeeper(uuid.uuid4(), uuid.uuid4(), attempt=1)
    assert await _StepHeartbeat(keeper)(1, 10) is None


def test_losing_the_lease_is_not_retryable() -> None:
    """There is nothing to retry: the step is already back in the queue or
    already running somewhere else."""
    assert StepLeaseLost("gone").retryable is False
