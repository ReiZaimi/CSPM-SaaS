"""The scan state machine: what may run, and what the steps add up to.

A scan was one Celery task that had to survive every subscription it covered. A
worker redeployed after reading nine subscriptions out of ten had read nothing,
fifty subscriptions were fifty sequential collections inside one thirty-minute
limit, and retrying one failure meant retrying everything that had worked.

The dependency rules and the summary are pure functions of a list of steps, so
they are tested as such -- no database, no Celery, no Azure. What needs
PostgreSQL is the claim, and that is exercised in the integration suite where
two concurrent claims can actually race.
"""

import uuid

from app.core.enums import ScanStatus, ScanStepKind, ScanStepStatus
from app.models.scan import ScanStep
from app.services import orchestrator


def step(
    kind: ScanStepKind,
    status: ScanStepStatus = ScanStepStatus.PENDING,
    *,
    account: uuid.UUID | None = None,
    error: str | None = None,
) -> ScanStep:
    made = ScanStep(
        organization_id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        kind=kind,
        status=status,
        cloud_account_id=account,
        error=error,
    )
    made.id = uuid.uuid4()
    return made


# ------------------------------------------------------------- what may run
def test_plan_runs_first_and_alone() -> None:
    """Nothing else knows its scope yet -- PLAN is what resolves it."""
    steps = [step(ScanStepKind.PLAN), step(ScanStepKind.ANALYZE)]
    assert orchestrator.runnable(steps) == [steps[0]]


def test_collection_waits_for_the_plan() -> None:
    """A COLLECT step left behind by a half-finished PLAN must wait rather than
    run against a scope nothing resolved."""
    steps = [
        step(ScanStepKind.PLAN, ScanStepStatus.RUNNING),
        step(ScanStepKind.COLLECT, account=uuid.uuid4()),
    ]
    assert orchestrator.runnable(steps) == []


def test_every_subscription_becomes_runnable_at_once() -> None:
    """The point of the split. Fifty subscriptions are fifty units a pool of
    workers takes in parallel, not fifty sequential reads inside one task."""
    plan = step(ScanStepKind.PLAN, ScanStepStatus.SUCCEEDED)
    collects = [step(ScanStepKind.COLLECT, account=uuid.uuid4()) for _ in range(3)]
    ready = orchestrator.runnable([plan, *collects, step(ScanStepKind.ANALYZE)])
    assert ready == collects


def test_analysis_waits_for_collection_to_settle() -> None:
    plan = step(ScanStepKind.PLAN, ScanStepStatus.SUCCEEDED)
    steps = [
        plan,
        step(ScanStepKind.COLLECT, ScanStepStatus.SUCCEEDED, account=uuid.uuid4()),
        step(ScanStepKind.COLLECT, ScanStepStatus.RUNNING, account=uuid.uuid4()),
        step(ScanStepKind.ANALYZE),
    ]
    assert orchestrator.runnable(steps) == []


def test_analysis_runs_even_when_a_subscription_could_not_be_read() -> None:
    """Settled, not succeeded, and the distinction is the product.

    A subscription CloudGuard could not read is a gap in the report. Holding the
    whole report back over it would turn a partial answer into no answer, which
    is the same overclaim as a PASS nobody earned, pointed the other way.
    """
    analyze = step(ScanStepKind.ANALYZE)
    steps = [
        step(ScanStepKind.PLAN, ScanStepStatus.SUCCEEDED),
        step(ScanStepKind.COLLECT, ScanStepStatus.SUCCEEDED, account=uuid.uuid4()),
        step(
            ScanStepKind.COLLECT,
            ScanStepStatus.FAILED,
            account=uuid.uuid4(),
            error="403",
        ),
        analyze,
    ]
    assert orchestrator.runnable(steps) == [analyze]


def test_a_claimed_step_is_not_offered_again() -> None:
    """Only PENDING is runnable, which is what stops a second advance handing
    the same step to a second worker."""
    plan = step(ScanStepKind.PLAN, ScanStepStatus.RUNNING)
    assert orchestrator.runnable([plan]) == []


# --------------------------------------------------------- what it adds up to
def test_a_scan_is_unfinished_while_anything_is_outstanding() -> None:
    steps = [
        step(ScanStepKind.PLAN, ScanStepStatus.SUCCEEDED),
        step(ScanStepKind.ANALYZE),
    ]
    finished, degraded, problems = orchestrator.summarize(steps)
    assert not finished
    assert not degraded
    assert problems == []


def test_a_scan_that_lost_a_subscription_is_partial_not_failed() -> None:
    """Nine subscriptions out of ten is nine subscriptions' worth of findings
    and one recorded gap, which is a report rather than a failure."""
    steps = [
        step(ScanStepKind.PLAN, ScanStepStatus.SUCCEEDED),
        step(ScanStepKind.COLLECT, ScanStepStatus.SUCCEEDED, account=uuid.uuid4()),
        step(
            ScanStepKind.COLLECT,
            ScanStepStatus.FAILED,
            account=uuid.uuid4(),
            error="Forbidden",
        ),
        step(ScanStepKind.ANALYZE, ScanStepStatus.SUCCEEDED),
    ]
    finished, degraded, problems = orchestrator.summarize(steps)

    assert finished and degraded
    assert any("Forbidden" in problem for problem in problems)
    assert orchestrator.status_for(steps) == ScanStatus.PARTIAL


def test_a_scan_whose_every_step_failed_has_failed() -> None:
    """The one case that is genuinely a failure rather than a gap: nothing was
    read and nothing was concluded."""
    steps = [
        step(ScanStepKind.PLAN, ScanStepStatus.FAILED, error="no scope"),
        step(ScanStepKind.ANALYZE, ScanStepStatus.SKIPPED),
    ]
    assert orchestrator.status_for(steps) == ScanStatus.FAILED


def test_a_clean_scan_completes() -> None:
    steps = [
        step(ScanStepKind.PLAN, ScanStepStatus.SUCCEEDED),
        step(ScanStepKind.COLLECT, ScanStepStatus.SUCCEEDED, account=uuid.uuid4()),
        step(ScanStepKind.ANALYZE, ScanStepStatus.SUCCEEDED),
    ]
    assert orchestrator.status_for(steps) == ScanStatus.COMPLETED


def test_a_running_scan_reports_the_stage_it_is_in() -> None:
    """Mapped onto the statuses that already exist rather than inventing a
    parallel vocabulary the frontend would have to learn."""
    collecting = [
        step(ScanStepKind.PLAN, ScanStepStatus.SUCCEEDED),
        step(ScanStepKind.COLLECT, ScanStepStatus.RUNNING, account=uuid.uuid4()),
        step(ScanStepKind.ANALYZE),
    ]
    assert orchestrator.status_for(collecting) == ScanStatus.DISCOVERING

    analyzing = [
        step(ScanStepKind.PLAN, ScanStepStatus.SUCCEEDED),
        step(ScanStepKind.COLLECT, ScanStepStatus.SUCCEEDED, account=uuid.uuid4()),
        step(ScanStepKind.ANALYZE, ScanStepStatus.RUNNING),
    ]
    assert orchestrator.status_for(analyzing) == ScanStatus.EVALUATING


def test_progress_counts_settled_steps() -> None:
    """Coarser than the per-listing count it replaces, and correct where that
    was not: a scan now runs across several workers, and a counter accumulated
    in one process could only describe the part that process ran."""
    steps = [
        step(ScanStepKind.PLAN, ScanStepStatus.SUCCEEDED),
        step(ScanStepKind.COLLECT, ScanStepStatus.SUCCEEDED, account=uuid.uuid4()),
        step(ScanStepKind.COLLECT, ScanStepStatus.RUNNING, account=uuid.uuid4()),
        step(ScanStepKind.ANALYZE),
    ]
    assert orchestrator.progress(steps) == (2, 4)


def test_a_scan_with_no_steps_is_not_reported_as_finished() -> None:
    """An empty set trivially satisfies "all settled", and reporting that as a
    completed scan would mean a scan whose steps were never created looked
    exactly like one that succeeded."""
    finished, _degraded, _problems = orchestrator.summarize([])
    assert not finished


# ------------------------------------------------------------- degradation
def test_a_scan_is_partial_when_a_listing_failed_inside_a_step() -> None:
    """The half the steps cannot see, and the half that happens most often.

    A COLLECT step that read a subscription but lost its storage listing to a
    403 *succeeded*: it collected, and it recorded the gap exactly as it should.
    The scan is still PARTIAL, because a rule somewhere lost its verdict --
    reporting COMPLETED over that is the same overclaim as a PASS nobody earned.

    Regression: when scan status moved to the orchestrator it was derived from
    the steps alone, and every such scan started reporting COMPLETED.
    """
    steps = [
        step(ScanStepKind.PLAN, ScanStepStatus.SUCCEEDED),
        step(ScanStepKind.COLLECT, ScanStepStatus.SUCCEEDED, account=uuid.uuid4()),
        step(ScanStepKind.ANALYZE, ScanStepStatus.SUCCEEDED),
    ]
    assert orchestrator.status_for(steps) == ScanStatus.COMPLETED
    assert orchestrator.status_for(steps, degraded=True) == ScanStatus.PARTIAL


def test_a_step_failure_degrades_a_scan_without_being_told() -> None:
    """The other source. Both are independent, and either is enough."""
    steps = [
        step(ScanStepKind.PLAN, ScanStepStatus.SUCCEEDED),
        step(
            ScanStepKind.COLLECT,
            ScanStepStatus.FAILED,
            account=uuid.uuid4(),
            error="403",
        ),
        step(ScanStepKind.ANALYZE, ScanStepStatus.SUCCEEDED),
    ]
    assert orchestrator.status_for(steps, degraded=False) == ScanStatus.PARTIAL
