"""Reports, generated on request rather than stored.

Two questions decide the shape of this, and both answers are "keep it simple
until something forces otherwise".

*Why not a background job?* Because a report is a read of data that is already
computed. Queueing it would buy the ability to survive a slow render, at the
cost of a jobs table, a polling endpoint, an artifact store and a retention
policy -- machinery whose only justification would be a report that takes long
enough to time out, and the technical report is bounded at
``MAX_TECHNICAL_FINDINGS`` precisely so it does not.

*Why not store the PDF?* Because a stored report is a claim about a moment that
outlives the evidence behind it, and CloudGuard would then owe the customer an
answer about which of five stored PDFs is current. Every report says on its
cover when its evidence was collected; regenerating is cheap and always
truthful.

HTML is offered beside PDF deliberately. It is the same document -- the PDF is
that HTML printed -- so a reader can look at a report without downloading one,
and a deployment whose native PDF libraries are missing still produces
something useful while that is fixed.
"""

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, Response

from app.core.deps import DbSession, Tenant
from app.core.errors import NotFound
from app.reports.render import render_html, render_pdf
from app.services.reports import build_report

router = APIRouter(prefix="/reports", tags=["reports"])

KINDS = {"executive", "technical"}


def _filename(kind: str, organization: str, extension: str) -> str:
    """A filename somebody can find again in a downloads folder.

    Slugged rather than passed through: an organization is named by its
    customer, and a name carrying a quote or a newline would break the
    Content-Disposition header it lands in.
    """
    slug = "".join(
        char if char.isalnum() else "-" for char in organization.lower()
    ).strip("-")
    slug = "-".join(part for part in slug.split("-") if part) or "organization"
    return f"cloudguard-{slug}-{kind}.{extension}"


@router.get("/{kind}")
async def get_report(
    kind: str,
    session: DbSession,
    tenant: Tenant,
    format: str = Query(default="pdf", pattern="^(pdf|html)$"),
) -> Response:
    """One report, rendered now from the current evidence."""
    if kind not in KINDS:
        raise NotFound(f"No such report: {kind}")

    report = await build_report(session, tenant.organization_id, technical=kind == "technical")
    name = report["organization"]["name"]

    if format == "html":
        return HTMLResponse(render_html(report))

    return Response(
        content=render_pdf(report),
        media_type="application/pdf",
        headers={
            # `attachment` rather than `inline`: this is a document somebody
            # asked to keep, and a PDF that opens in a tab and has to be saved
            # from there is one more step in the way of that.
            "Content-Disposition": f'attachment; filename="{_filename(kind, name, "pdf")}"',
        },
    )
