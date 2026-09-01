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
from app.core.errors import NotFound, ValidationFailed
from app.reports.render import render_html, render_pdf
from app.services.reports import (
    DEFAULT_WINDOW_DAYS,
    MAX_WINDOW_DAYS,
    OPTIONAL_SECTIONS,
    build_report,
)

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
    days: int = Query(
        default=DEFAULT_WINDOW_DAYS,
        ge=1,
        le=MAX_WINDOW_DAYS,
        description="Activity window: how far back verified fixes, completed "
        "work and the trend line reach. It does not filter the posture, which "
        "is a reading of now.",
    ),
    sections: str | None = Query(
        default=None,
        description=(
            "Comma-separated optional sections to include. Omit the parameter "
            "for all of them; pass it empty for none. The posture block and "
            "the evidence caveats are not optional either way."
        ),
    ),
) -> Response:
    """One report, rendered now from the current evidence."""
    if kind not in KINDS:
        raise NotFound(f"No such report: {kind}")

    chosen: frozenset[str] | None = None
    if sections is not None:
        # An absent parameter means "all of them"; an empty one means "none",
        # which is a posture-only report and a real thing to want. The two are
        # distinguished rather than collapsed, because collapsing them would
        # make the emptiest request produce the fullest document.
        requested = [part.strip() for part in sections.split(",") if part.strip()]
        # Named rather than ignored. A misspelled section that silently
        # produced a report without it would be a document quietly missing a
        # part somebody asked for, which is the one failure mode a report
        # cannot afford.
        unknown = sorted(set(requested) - set(OPTIONAL_SECTIONS))
        if unknown:
            raise ValidationFailed(
                f"No such report section: {', '.join(unknown)}. "
                f"Choose from: {', '.join(OPTIONAL_SECTIONS)}."
            )
        chosen = frozenset(requested)

    report = await build_report(
        session,
        tenant.organization_id,
        technical=kind == "technical",
        sections=chosen,
        window_days=days,
    )
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
