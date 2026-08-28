from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import func, select

from app.core.deps import DbSession, Tenant
from app.core.enums import ScanStatus
from app.core.errors import ConflictError, ScanNotFound, ValidationFailed, envelope
from app.core.logging import get_logger
from app.models.scan import Scan, ScanEvaluationGap, ScanRuleResult
from app.schemas.scan import CoverageOut, ScanCreate, ScanDetailOut, ScanOut
from app.services import cloud_accounts as accounts_service
from app.services import scans as scans_service
from app.workers.scan_tasks import run_scan

log = get_logger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def create_scan(payload: ScanCreate, session: DbSession, tenant: Tenant) -> dict:
    tenant.require_write()
    account = await accounts_service.get_cloud_account(
        session, tenant, payload.cloud_account_id
    )

    if not account.is_scannable:
        raise ValidationFailed(
            "This connection is not ready to scan. Grant admin consent, assign the "
            "Reader role, then validate the connection."
        )

    running = (
        await session.execute(
            select(Scan).where(
                Scan.cloud_account_id == account.id,
                Scan.status.in_(
                    [
                        ScanStatus.QUEUED,
                        ScanStatus.DISCOVERING,
                        ScanStatus.NORMALIZING,
                        ScanStatus.EVALUATING,
                        ScanStatus.CALCULATING_RISK,
                    ]
                ),
            )
        )
    ).scalar_one_or_none()
    if running is not None:
        raise ConflictError("A scan is already running for this connection")

    scan = Scan(
        organization_id=tenant.organization_id,
        cloud_account_id=account.id,
        status=ScanStatus.QUEUED,
        # Recorded from the authenticated user, never from the request body.
        triggered_by_user_id=tenant.user.id,
    )
    session.add(scan)
    await session.commit()

    # Only the id crosses the queue. The worker re-reads the tenant boundary
    # from the scan row rather than trusting the message.
    try:
        run_scan.delay(str(scan.id))
    except Exception as exc:
        # The row is already committed, so a broker that refused the message
        # would otherwise leave a scan queued that nothing will ever collect --
        # indistinguishable, on screen, from one about to start.
        log.warning("scan.enqueue_failed", scan_id=str(scan.id), error=str(exc))
        scan.status = ScanStatus.FAILED
        scan.error_message = (
            "CloudGuard could not put this scan on the queue. The task broker "
            f"is unreachable: {exc}"
        )
        await session.commit()

    return envelope(ScanOut.model_validate(scan).model_dump(mode="json"))


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """Stop a scan that has not finished.

    Cancelling a queued scan is the common case and the reason this exists: a
    scan sits queued until a worker collects it, and if none is running it sits
    there indefinitely. The pipeline re-reads the status before it starts, so a
    task collected after cancellation stops rather than writing findings nobody
    asked for.
    """
    tenant.require_write()
    scan = (
        await session.execute(
            select(Scan).where(
                Scan.id == scan_id,
                Scan.organization_id == tenant.organization_id,
            )
        )
    ).scalar_one_or_none()
    if scan is None:
        raise ScanNotFound()

    if scan.status.is_terminal:
        raise ConflictError(f"This scan has already finished ({scan.status.value}).")

    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.now(UTC)
    scan.error_message = "Cancelled."
    await session.commit()
    return envelope(ScanOut.model_validate(scan).model_dump(mode="json"))


@router.get("")
async def list_scans(session: DbSession, tenant: Tenant, limit: int = 25) -> dict:
    rows = (
        (
            await session.execute(
                select(Scan)
                .where(Scan.organization_id == tenant.organization_id)
                .order_by(Scan.created_at.desc())
                .limit(min(limit, 100))
            )
        )
        .scalars()
        .all()
    )
    return envelope([ScanOut.model_validate(s).model_dump(mode="json") for s in rows])


@router.get("/{scan_id}/detail")
async def get_scan_detail(scan_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """One scan, with its scope, identity and severity breakdown."""
    scan = await scans_service.get_scan(session, tenant, scan_id)
    data = ScanDetailOut.model_validate(scan).model_dump(mode="json")
    data["scope"] = await scans_service.scan_context(session, scan)
    data["findings_by_severity"] = await scans_service.severity_breakdown(session, scan)
    data["purgeable_finding_count"] = await scans_service.findings_attributable_to(
        session, scan
    )
    return envelope(data)


@router.get("/{scan_id}")
async def get_scan(scan_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    scan = (
        await session.execute(
            select(Scan).where(
                Scan.id == scan_id, Scan.organization_id == tenant.organization_id
            )
        )
    ).scalar_one_or_none()
    if scan is None:
        raise ScanNotFound()
    return envelope(ScanOut.model_validate(scan).model_dump(mode="json"))


@router.delete("/{scan_id}", status_code=status.HTTP_200_OK)
async def delete_scan(
    scan_id: UUID,
    session: DbSession,
    tenant: Tenant,
    purge_findings: bool = False,
) -> dict:
    """Delete a scan record, and optionally the findings it last detected.

    ``purge_findings`` defaults to false because the two are different acts:
    deleting the record prunes an execution log, while purging also discards
    what was found. Resolved findings are never purged either way -- each one
    is the evidence that a fix was verified.
    """
    tenant.require_write()
    result = await scans_service.delete_scan(
        session, tenant, scan_id, purge_findings=purge_findings
    )
    return envelope(result)


@router.get("/{scan_id}/coverage")
async def scan_coverage(scan_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """What this scan could and could not determine.

    Reported apart from the security score: a user asking "why is my score 84?"
    should not have to understand coverage maths to get an answer, and a user
    asking "what did you miss?" deserves a straight one.
    """
    totals = (
        await session.execute(
            select(
                func.coalesce(func.sum(ScanRuleResult.passed_count), 0),
                func.coalesce(func.sum(ScanRuleResult.failed_count), 0),
                func.coalesce(func.sum(ScanRuleResult.unknown_count), 0),
                func.coalesce(func.sum(ScanRuleResult.evaluated_count), 0),
            ).where(
                ScanRuleResult.scan_id == scan_id,
                ScanRuleResult.organization_id == tenant.organization_id,
            )
        )
    ).one()
    passed, failed, unknown, evaluated = (int(v) for v in totals)

    gaps = (
        (
            await session.execute(
                select(ScanEvaluationGap)
                .where(
                    ScanEvaluationGap.scan_id == scan_id,
                    ScanEvaluationGap.organization_id == tenant.organization_id,
                )
                .limit(200)
            )
        )
        .scalars()
        .all()
    )

    conclusive = passed + failed
    denominator = conclusive + unknown
    return envelope(
        CoverageOut(
            coverage_ratio=round(conclusive / denominator, 4) if denominator else 1.0,
            evaluated=evaluated,
            conclusive=conclusive,
            unknown=unknown,
            gaps=[
                {
                    "rule_id": g.rule_id,
                    "resource_id": str(g.resource_id) if g.resource_id else None,
                    "reason": g.reason,
                }
                for g in gaps
            ],
        ).model_dump()
    )
