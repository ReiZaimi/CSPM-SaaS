"""Confirming that a fix took, and saying honestly when it cannot be confirmed.

Three things happen here, and the middle one is the whole feature.

**A claim is recorded.** When a customer marks remediation done, CloudGuard
writes down what it now expects to see: this rule, on this asset, should PASS.
Before that the expectation existed only in the customer's head, so nothing
could look for it and nothing could report on it.

**Observations settle the claim.** Every scan that reaches a verdict on that
pair settles the verification or spends one attempt of a backoff. The backoff
exists because a cloud takes time to agree with itself: a check run a minute
after a configuration change reports the environment as it was, and answering
"still failing" then is how a verification feature teaches its customers not to
believe it.

**The answer distinguishes three failures.** Not verified covers "the fix did
not work", "CloudGuard could not see" and "it is too soon", and those need
three different sentences to three different people. That is the FAIL/UNKNOWN
distinction the rule algebra already draws, carried up to the one screen where
somebody is being told whether their work counted.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import RuleState, VerificationStatus
from app.core.logging import get_logger
from app.models.cloud_account import CloudAccount
from app.models.finding import Finding
from app.models.remediation import RemediationTask
from app.models.resource import ResourceRecord
from app.models.scan import Scan
from app.models.verification import RemediationVerification

log = get_logger(__name__)

# How long to wait before each attempt, measured from the previous one. Four
# attempts over roughly five hours.
#
# The first gap is the important one and it is not about load. Azure applies a
# configuration change to the control plane before every read path agrees about
# it, so a check a few seconds after the fix reads the old state and is right to
# -- the environment genuinely still said that when it was asked. Five minutes
# covers the ordinary case; the widening gaps cover the ones that take a policy
# evaluation cycle or a replication hop.
#
# It stops at four rather than retrying indefinitely because an answer is the
# product. A verification that never settles is the same silence this table was
# built to remove, dressed up as diligence.
ATTEMPT_SCHEDULE: tuple[timedelta, ...] = (
    timedelta(minutes=5),
    timedelta(minutes=15),
    timedelta(hours=1),
    timedelta(hours=4),
)

# How many verifications one scheduler tick will start scans for. The same
# ceiling the scheduled-scan sweep uses, and for the same reason: a tick that
# tried to serve every tenant at once would be one slow tenant away from serving
# none of them.
DUE_START_LIMIT = 20


def next_attempt_after(attempts: int, *, now: datetime) -> datetime | None:
    """When to look again after ``attempts`` have been made, or None if done."""
    if attempts >= len(ATTEMPT_SCHEDULE):
        return None
    return now + ATTEMPT_SCHEDULE[attempts]


async def open_verification(
    session: AsyncSession,
    *,
    organization_id: UUID,
    finding: Finding,
    task: RemediationTask | None = None,
    claimed_by_user_id: UUID | None = None,
    now: datetime | None = None,
) -> RemediationVerification:
    """Record that somebody says this finding is fixed, and start checking.

    Restating the claim -- marking the same task done twice -- refreshes the
    existing verification rather than opening a second. Two pending rows would
    spend two sets of attempts answering one question, and the second would
    report on work the first had already settled.
    """
    moment = now or datetime.now(UTC)
    existing = await pending_for(session, organization_id, finding.id)

    account_id, connection_id = await _scope_of(session, organization_id, finding)

    if existing is not None:
        existing.claimed_at = moment
        existing.claimed_by_user_id = claimed_by_user_id
        existing.remediation_task_id = task.id if task is not None else None
        # The clock restarts, and so do the attempts: the customer has done
        # something else since, and the attempts already spent were spent
        # against the previous claim.
        existing.attempts = 0
        existing.observed_failure = False
        existing.last_state = None
        existing.next_attempt_at = next_attempt_after(0, now=moment)
        existing.detail = None
        return existing

    verification = RemediationVerification(
        organization_id=organization_id,
        finding_id=finding.id,
        remediation_task_id=task.id if task is not None else None,
        rule_id=finding.rule_id,
        resource_id=finding.resource_id,
        cloud_account_id=account_id,
        connection_id=connection_id,
        status=VerificationStatus.PENDING,
        claimed_at=moment,
        claimed_by_user_id=claimed_by_user_id,
        next_attempt_at=next_attempt_after(0, now=moment),
    )
    session.add(verification)
    log.info(
        "verification.opened",
        finding_id=str(finding.id),
        rule_id=finding.rule_id,
    )
    return verification


async def abandon(
    session: AsyncSession,
    organization_id: UUID,
    finding_id: UUID,
    *,
    reason: str,
    now: datetime | None = None,
) -> None:
    """Stop asking. The question has been answered some other way.

    A finding whose risk was accepted, or whose asset is gone, is not a fix that
    failed to verify -- and leaving it PENDING would have the scheduler starting
    scans to settle a question nobody is waiting on.
    """
    verification = await pending_for(session, organization_id, finding_id)
    if verification is None:
        return
    verification.status = VerificationStatus.ABANDONED
    verification.settled_at = now or datetime.now(UTC)
    verification.next_attempt_at = None
    verification.detail = reason


async def pending_for(
    session: AsyncSession, organization_id: UUID, finding_id: UUID
) -> RemediationVerification | None:
    return (
        await session.execute(
            select(RemediationVerification).where(
                RemediationVerification.organization_id == organization_id,
                RemediationVerification.finding_id == finding_id,
                RemediationVerification.status == VerificationStatus.PENDING,
            )
        )
    ).scalar_one_or_none()


def observe(
    verification: RemediationVerification,
    state: RuleState,
    *,
    scan_id: UUID,
    now: datetime,
) -> VerificationStatus:
    """Apply one scan's verdict to a pending verification.

    Pure apart from the row it mutates, so the policy can be tested without a
    database or a scan -- which matters, because this is where the product's
    strongest claim is either earned or overstated.

    ``NOT_APPLICABLE`` is treated as a verdict that the problem is gone, not as
    a non-answer: a rule that no longer applies to an asset the finding was
    raised against means the asset is no longer the kind of thing the rule
    judges, which is a fix by reconfiguration rather than by setting.
    """
    verification.attempts += 1
    verification.last_attempt_at = now
    verification.last_state = state

    if state in (RuleState.PASS, RuleState.NOT_APPLICABLE):
        verification.status = VerificationStatus.VERIFIED
        verification.settled_at = now
        verification.next_attempt_at = None
        verification.verified_by_scan_id = scan_id
        verification.detail = (
            "The check that raised this finding now passes on the same asset."
            if state is RuleState.PASS
            else "The rule no longer applies to this asset."
        )
        return verification.status

    if state is RuleState.FAIL:
        verification.observed_failure = True

    following = next_attempt_after(verification.attempts, now=now)
    if following is not None:
        # Still within the backoff. Deliberately not reported as a failure: the
        # honest reading of an early FAIL is that the environment had not
        # finished agreeing with itself, and saying otherwise is what makes a
        # customer stop believing the eventual answer.
        verification.next_attempt_at = following
        verification.detail = (
            "Checked, and the environment does not show the fix yet. "
            "CloudGuard will look again."
            if state is RuleState.FAIL
            else "CloudGuard could not read enough to tell yet, and will try again."
        )
        return VerificationStatus.PENDING

    verification.status = (
        VerificationStatus.STILL_FAILING
        if verification.observed_failure
        else VerificationStatus.INSUFFICIENT_EVIDENCE
    )
    verification.settled_at = now
    verification.next_attempt_at = None
    verification.verified_by_scan_id = scan_id
    verification.detail = (
        f"Checked {verification.attempts} times over "
        f"{_span(verification, now)}, and the check still fails."
        if verification.observed_failure
        else (
            "CloudGuard could not gather the evidence this check needs, so it "
            "cannot say whether the fix worked. This is a gap in what CloudGuard "
            "could read, not a failed fix."
        )
    )
    return verification.status


async def due(
    session: AsyncSession, *, now: datetime | None = None, limit: int = DUE_START_LIMIT
) -> list[RemediationVerification]:
    """Verifications whose next attempt is owed.

    Ordered oldest first, so a backlog is worked through in the order the
    customers asked rather than in whatever order the index happens to hold.
    """
    moment = now or datetime.now(UTC)
    return list(
        (
            await session.execute(
                select(RemediationVerification)
                .where(
                    RemediationVerification.status == VerificationStatus.PENDING,
                    RemediationVerification.next_attempt_at.is_not(None),
                    RemediationVerification.next_attempt_at <= moment,
                )
                .order_by(RemediationVerification.next_attempt_at)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )


async def _scope_of(
    session: AsyncSession, organization_id: UUID, finding: Finding
) -> tuple[UUID | None, UUID | None]:
    """Which subscription and connection have to be read to settle this.

    Read off the asset first, because a finding about a directory user belongs
    to no subscription at all -- a scheduler that assumed one would either start
    nothing or start a scan of the wrong scope.

    Falling back to the scan that detected the finding, which matters for the
    aggregate-scope findings that are about a tenant rather than any asset. A
    verification with neither scope can be settled by no scan at all: nothing
    would ever match it, and it would sit pending for ever while the scheduler
    tried to serve it.
    """
    if finding.resource_id is not None:
        resource = await session.get(ResourceRecord, finding.resource_id)
        if resource is not None and resource.organization_id == organization_id:
            return resource.cloud_account_id, resource.connection_id

    if finding.scan_id is None:
        return None, None
    scan = await session.get(Scan, finding.scan_id)
    if scan is None or scan.organization_id != organization_id:
        return None, None
    if scan.cloud_account_id is not None:
        account = await session.get(CloudAccount, scan.cloud_account_id)
        return scan.cloud_account_id, account.connection_id if account else None
    return None, scan.connection_id


def _span(verification: RemediationVerification, now: datetime) -> str:
    claimed = verification.claimed_at
    if claimed.tzinfo is None:
        claimed = claimed.replace(tzinfo=UTC)
    hours = max(1, round((now - claimed).total_seconds() / 3600))
    return "an hour" if hours == 1 else f"{hours} hours"
