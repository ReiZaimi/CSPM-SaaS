from typing import Any
from uuid import UUID

from fastapi import APIRouter, Query, status
from sqlalchemy import case, func, or_, select
from sqlalchemy.sql.elements import UnaryExpression

from app.core.deps import DbSession, Tenant
from app.core.enums import FindingStatus, ScanStatus, Severity
from app.core.errors import ConflictError, ValidationFailed, envelope
from app.core.vocabulary import words
from app.graph import Path
from app.models.finding import Finding, FindingEvidence
from app.models.resource import ResourceRecord
from app.models.scan import Scan
from app.schemas.finding import (
    AcceptRiskRequest,
    EvidenceCitationOut,
    FindingEventOut,
    FindingOut,
    ResourceSummary,
    RiskOut,
    VerificationOut,
)
from app.services import cloud_accounts as accounts_service
from app.services import findings as service
from app.services import graph as graph_service
from app.services import scans as scans_service
from app.services.graph import serialize_path
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
    evidence_id: UUID | None = None,
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
    if evidence_id:
        # "What rests on this reading" -- the citation chain walked from the
        # evidence end, which is what a person looking at a failed or stale
        # listing on the scans page is actually asking.
        #
        # Filtered on the reading rather than on its key, because a key spans
        # every subscription and every scan that read it: the count offered
        # beside a reading and the rows this returns have to be the same set,
        # or the link is a number that does not survive being clicked.
        stmt = stmt.where(
            Finding.id.in_(
                select(FindingEvidence.finding_id).where(
                    FindingEvidence.organization_id == tenant.organization_id,
                    FindingEvidence.evidence_id == evidence_id,
                )
            )
        )
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


@router.get("/{finding_id}/attack-paths")
async def finding_attack_paths(
    finding_id: UUID, session: DbSession, tenant: Tenant
) -> dict:
    """The routes this finding's asset sits on, if any.

    Its own endpoint rather than a field on the finding, because it costs a
    graph build and the finding page must not wait on one to say what is wrong.
    The page asks for this after it has rendered, and a reader who never scrolls
    to it has paid nothing.

    Membership is asked of the whole route, not of its endpoints: a person
    looking at a misconfiguration on the jump box at the start and a person
    looking at one on the storage account at the end are looking at the same
    problem, and both deserve to be told it is a route rather than an isolated
    fault.
    """
    finding = await service.get_finding(session, tenant, finding_id)

    # A tenant-wide finding has no asset, so it cannot be on a route. Answered
    # as an empty list rather than a 404: "this finding is on no path" is a
    # true and useful answer, and the page renders it as one.
    if finding.resource_id is None:
        return envelope([], {"total": 0, "asset": None})

    resource = await session.get(ResourceRecord, finding.resource_id)
    if resource is None:
        return envelope([], {"total": 0, "asset": None})

    graph = await graph_service.load_graph(session, tenant.organization_id)
    paths = graph.paths_through(resource.provider_resource_id)

    return envelope(
        [
            # Where on the route this asset sits, which changes what the reader
            # should do about it: an entry point is how somebody gets in, a
            # target is what they are coming for, and a hop in between is the
            # link most likely worth cutting.
            {
                **serialize_path(path),
                "asset_role": _role_on_path(path, resource.provider_resource_id),
            }
            for path in paths
        ],
        {"total": len(paths), "asset": resource.provider_resource_id},
    )


@router.get("/{finding_id}/provenance")
async def finding_provenance(
    finding_id: UUID, session: DbSession, tenant: Tenant
) -> dict:
    """How CloudGuard knows: the readings this finding rests on.

    The finding already carries an *excerpt* of its evidence. This is the
    citation -- which listing, taken when, under which permissions, and the hash
    of the bytes -- which is the difference between a claim a customer has to
    accept and one they can check.

    Its own endpoint rather than a field on the finding, for the same reason
    ``/attack-paths`` is: the page answering "what is wrong" must not wait on a
    question most readers never ask.

    ``evidence: null`` means no citation was recorded, which for a finding
    raised before this existed is a fact about CloudGuard rather than about the
    finding. An empty list would say the rule reads nothing, and the two must
    not be answered the same way -- a product that cannot tell them apart is
    back to asking to be believed.
    """
    finding = await service.get_finding(session, tenant, finding_id)
    citations = await service.load_provenance(session, tenant, finding)

    return envelope(
        {
            "rule_id": finding.rule_id,
            # The rule as it was when this finding was raised, not as it is now.
            # A citation to evidence read by a rule that has since changed its
            # mind is a different claim, and the version is what says so.
            "rule_version": finding.rule_version,
            "evidence": (
                [EvidenceCitationOut(**row).model_dump() for row in citations]
                if citations is not None
                else None
            ),
        },
        {
            "total": len(citations) if citations is not None else 0,
            "recorded": citations is not None,
        },
    )


def _role_on_path(path: Path, resource_id: str) -> str:
    if path.entry.provider_resource_id == resource_id:
        return "ENTRY"
    if path.target.provider_resource_id == resource_id:
        return "TARGET"
    return "STEP"


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
            scope_words = words(resource.provider)
            raise ValidationFailed(
                f"This finding is about the {scope_words.directory}, and the "
                f"connection it came from has no {scope_words.account} ready to "
                "scan. Validate the connection, then try again."
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
