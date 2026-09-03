"""Compliance: the catalogue, this organization's assessment, and the export.

The chain the product claims -- reading, rule, control, framework -- is only
worth anything if somebody can take it out of the browser, so the export is
part of this router rather than an afterthought bolted to reports. It is a
document rather than an envelope for the same reason a report is: the caller is
saving a file, not reading an API response.
"""

import json

from fastapi import APIRouter, Query
from fastapi.responses import Response

from app.compliance.export import export_filename, to_csv
from app.core.deps import DbSession, Tenant
from app.core.errors import NotFound, envelope
from app.models.organization import Organization
from app.services import compliance as service

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("")
async def list_frameworks(session: DbSession, tenant: Tenant) -> dict:
    return envelope(await service.list_frameworks(session, tenant.organization_id))


# Declared before ``/{framework_id}``: FastAPI matches in order, and the
# parameterised route would otherwise swallow this and answer with a framework
# named "export".
@router.get("/{framework_id}/export")
async def export_framework(
    framework_id: str,
    session: DbSession,
    tenant: Tenant,
    format: str = Query(default="csv", pattern="^(csv|json)$"),
) -> Response:
    """One framework's assessment, as a file.

    CSV for the spreadsheet an audit is actually run from, JSON for a GRC
    platform that would otherwise have somebody retyping it. Both carry the
    same thing: every control, its verdict, the rules behind that verdict and
    the provider readings behind those -- including for the controls that
    passed, which is the half a screen tends to leave out and an auditor asks
    about first.
    """
    organization = await session.get(Organization, tenant.organization_id)
    payload = await service.build_export(
        session,
        tenant.organization_id,
        framework_id,
        organization_name=organization.name if organization else "organization",
    )
    if payload is None:
        raise NotFound("Framework not found")

    if format == "json":
        return Response(
            content=json.dumps(payload, indent=2),
            media_type="application/json",
            headers=_attachment(payload["organization"], framework_id, "json"),
        )

    return Response(
        content=to_csv(payload),
        # ``charset=utf-8`` stated rather than assumed: control titles carry
        # non-ASCII characters, and a spreadsheet that guesses the encoding
        # guesses Latin-1 and renders them as mojibake.
        media_type="text/csv; charset=utf-8",
        headers=_attachment(payload["organization"], framework_id, "csv"),
    )


def _attachment(organization: str, framework_id: str, extension: str) -> dict[str, str]:
    name = export_filename(organization, framework_id, extension)
    return {"Content-Disposition": f'attachment; filename="{name}"'}


@router.get("/{framework_id}")
async def get_framework(framework_id: str, session: DbSession, tenant: Tenant) -> dict:
    detail = await service.get_framework_detail(session, tenant.organization_id, framework_id)
    if detail is None:
        raise NotFound("Framework not found")
    return envelope(detail)
