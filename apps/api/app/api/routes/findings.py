from typing import Any
from uuid import UUID

from fastapi import APIRouter, Query, status
from sqlalchemy import case, func, or_, select
from sqlalchemy.sql.elements import UnaryExpression

from app.core.deps import DbSession, Tenant
from app.core.enums import FindingStatus, ScanStatus, Severity
from app.core.errors import ConflictError, ValidationFailed, envelope
from app.models.finding import Finding
from app.models.resource import ResourceRecord
from app.models.scan import Scan
from app.schemas.finding import (
    AcceptRiskRequest,
    FindingEventOut,
    FindingOut,
    ResourceSummary,
    RiskOut,
    VerificationOut,
)
from app.services import cloud_accounts as accounts_service
from app.services import findings as service
from app.services import scans as scans_service
from app.workers.scan_tasks import run_scan

router = APIRouter(prefix="/findings", tags=["findings"])

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

# The same ranking expressed for the database, so "worst first" survives
# pagination. Sorting severity in Python could only ever order the page it was
# handed, which puts the CRITICAL on page four below the LOW on page one.
SEVERITY_SORT = case(SEVERITY_ORDER, value=Finding.severity, else_=9)

SORTS: dict[str, tuple[UnaryExpression[Any], ...]] = {
    # Risk first by default: the product's claim is that it tells you what
    # matters here, not what the rulebook says in the abstract.
    "risk": (Finding.risk_score.desc().nullslast(), Finding.last_detected_at.desc()),
    "severity": (SEVERITY_SORT.asc(), Finding.risk_score.desc().nullslast()),
    "recent": (Finding.last_detected_at.desc(),),
}


@router.get("")
async def list_findings(
    session: DbSession,
    tenant: Tenant,
    severity: Severity | None = None,
    finding_status: FindingStatus | None = Query(default=None, alias="status"),
    rule_id: str | None = None,
    resource_id: UUID | None = None,
    environment: str | None = None,
    search: str | None = None,
    sort: str = Query(default="risk", pattern="^(risk|severity|recent)$"),
    limit: int = Query(default=100, le=500),
    offset: int = 0,
) -> dict:
    """Findings, filtered and ordered by the database rather than by the client.

    ``search`` and ``sort`` are here because the alternative is worse than a
    missing feature. A page that filters and orders the rows it happens to hold
    searches one page of an estate and reports "nothing matches" for the rest --
    a false negative wearing an answer's clothes, in the one product where that
    is least acceptable.
    """
    stmt = (
        select(Finding, ResourceRecord)
        .outerjoin(ResourceRecord, ResourceRecord.id == Finding.resource_id)
        .where(Finding.organization_id == tenant.organization_id)
    )

    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if finding_status:
        stmt = stmt.where(Finding.status == finding_status)
    if rule_id:
        stmt = stmt.where(Finding.rule_id == rule_id)
    if resource_id:
        stmt = stmt.where(Finding.resource_id == resource_id)
    if environment:
        stmt = stmt.where(ResourceRecord.environment == environment)
    if search:
        # Three ways a person names the same finding: what it is called, the
        # rule that raised it, and the resource it was found on.
        needle = f"%{search}%"
        stmt = stmt.where(
            or_(
                Finding.title.ilike(needle),
                Finding.rule_id.ilike(needle),
                ResourceRecord.name.ilike(needle),
            )
        )

    total = (
        await session.execute(select(func.count()).select_from(stmt.subquery()))
    ).scalar_one()

    rows = (
        await session.execute(
            stmt.order_by(*SORTS[sort]).limit(limit).offset(offset)
        )
    ).all()

    payload = []
    for finding, resource in rows:
        item = FindingOut.model_validate(finding).model_dump(mode="json")
        item["resource"] = (
            ResourceSummary.model_validate(resource).model_dump(mode="json")
            if resource
            else None
        )
        payload.append(item)

    return envelope(payload, {"total": total, "limit": limit, "offset": offset})


@router.get("/{finding_id}")
async def get_finding(finding_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    finding = await service.get_finding(session, tenant, finding_id)
    detail = await service.load_detail(session, tenant, finding)

    payload = FindingOut.model_validate(finding).model_dump(mode="json")
    payload["resource"] = (
        ResourceSummary.model_validate(detail["resource"]).model_dump(mode="json")
        if detail["resource"]
        else None
    )
    payload["risk"] = (
        RiskOut.model_validate(detail["risk"]).model_dump(mode="json")
        if detail["risk"]
        else None
    )
    payload["priority"] = detail["priority"].value
    payload["estimated_effort_minutes"] = detail["estimated_effort_minutes"]
    # Null until somebody claims a fix. Present afterwards whether or not
    # CloudGuard has settled it -- "checking, and it has not appeared yet" is
    # the answer a customer who has just done the work is waiting for.
    payload["timeline"] = [
        FindingEventOut.model_validate(event).model_dump(mode="json")
        for event in detail["timeline"]
    ]
    payload["verification"] = (
        VerificationOut.model_validate(detail["verification"]).model_dump(mode="json")
        if detail["verification"]
        else None
    )
    payload.update(service.rule_metadata(finding.rule_id))
    return envelope(payload)


@router.post("/{finding_id}/accept-risk")
async def accept_risk(
    finding_id: UUID, payload: AcceptRiskRequest, session: DbSession, tenant: Tenant
) -> dict:
    tenant.require_write()
    finding = await service.get_finding(session, tenant, finding_id)
    finding = await service.accept_risk(
        session, tenant, finding, payload.reason, payload.expires_at
    )
    return envelope(FindingOut.model_validate(finding).model_dump(mode="json"))


@router.post("/{finding_id}/status")
async def set_finding_status(
    finding_id: UUID,
    new_status: FindingStatus,
    session: DbSession,
    tenant: Tenant,
) -> dict:
    tenant.require_write()
    finding = await service.get_finding(session, tenant, finding_id)
    finding = await service.set_status(session, tenant, finding, new_status)
    return envelope(FindingOut.model_validate(finding).model_dump(mode="json"))


@router.post("/{finding_id}/rescan", status_code=status.HTTP_202_ACCEPTED)
async def rescan_finding(finding_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """Re-check the environment after a fix.

    This is the verification step, and it is a full scan rather than a
    single-rule re-check: fixing one thing frequently changes another, and a
    narrow re-check would report a fix that a wider view would contradict. If
    the rule now passes, the pipeline resolves the finding on its own.
    """
    tenant.require_write()
    finding = await service.get_finding(session, tenant, finding_id)

    resource = (
        await session.get(ResourceRecord, finding.resource_id)
        if finding.resource_id
        else None
    )
    if resource is None:
        raise ValidationFailed(
            "This finding is not tied to a single resource. Run a full scan instead."
        )

    # A directory asset lives in the tenant and in no subscription, so there is
    # no account id on it to rescan. Any scannable subscription under the same
    # connection does the job: a scan resolves its connection from whichever
    # account it covers and reads the directory once through that, so the
    # cheapest scan available still re-reads the thing this finding is about.
    if resource.cloud_account_id is None:
        account = await accounts_service.first_scannable_account(
            session, tenant, resource.connection_id
        )
        if account is None:
            raise ValidationFailed(
                "This finding is about the tenant directory, and the connection "
                "it came from has no subscription ready to scan. Validate the "
                "connection, then try again."
            )
    else:
        account = await accounts_service.get_cloud_account(
            session, tenant, resource.cloud_account_id
        )
    if not account.is_scannable:
        raise ValidationFailed("This connection is not ready to scan")

    await scans_service.lock_scan_target(
        session, tenant.organization_id, account.connection_id, account.id
    )
    if await scans_service.scan_in_flight(
        session, tenant.organization_id, account.connection_id, account.id
    ):
        raise ConflictError("A scan is already running for this connection")

    # Deliberately narrowed to the one subscription this finding lives in, even
    # when the connection spans several. Re-reading a whole tenant to verify one
    # fix is a cost the customer did not ask for, and the auto-resolve path only
    # needs the subscription that holds the resource.
    scan = Scan(
        organization_id=tenant.organization_id,
        cloud_account_id=account.id,
        status=ScanStatus.QUEUED,
    )
    session.add(scan)
    await service.record_audit(
        session,
        tenant,
        action="finding.rescan_requested",
        resource_type="finding",
        resource_id=finding.id,
        metadata={"rule_id": finding.rule_id},
    )
    await session.commit()

    run_scan.delay(str(scan.id))
    return envelope(
        {
            "scan_id": str(scan.id),
            "finding_id": str(finding.id),
            "message": (
                "Rescan queued. If the issue is fixed, CloudGuard will resolve this "
                "finding automatically when the scan completes."
            ),
        }
    )
