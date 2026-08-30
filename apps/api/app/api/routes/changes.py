"""What moved in the environment, rather than what is true in it now.

The first question after a week of somebody else's deployments, and until the
change events existed it was answerable only by diffing snapshot blobs by hand.

Deliberately a feed of *transitions*, not a diff of two scans. A scan that finds
nothing different contributes nothing here, so an empty week reads as an empty
week rather than as a wall of rows saying everything is still where it was.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.core.deps import DbSession, Tenant
from app.core.enums import AssetChange
from app.core.errors import envelope
from app.models.history import AssetChangeEvent
from app.models.resource import ResourceRecord

router = APIRouter(prefix="/changes", tags=["changes"])

# How far back the feed looks when nobody says. A week, because that is the
# span the question is usually asked over -- "what changed while I was away".
DEFAULT_WINDOW_DAYS = 7


@router.get("")
async def list_changes(
    session: DbSession,
    tenant: Tenant,
    days: int = Query(default=DEFAULT_WINDOW_DAYS, ge=1, le=90),
    change: AssetChange | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
) -> dict:
    """Asset changes, newest first.

    Joined to the asset so a row is readable on its own. A feed of resource ids
    would be technically complete and would make the reader look up every line
    to find out whether it mattered.
    """
    since = datetime.now(UTC) - timedelta(days=days)

    stmt = (
        select(AssetChangeEvent, ResourceRecord)
        .join(ResourceRecord, ResourceRecord.id == AssetChangeEvent.resource_id)
        .where(
            AssetChangeEvent.organization_id == tenant.organization_id,
            AssetChangeEvent.observed_at >= since,
        )
    )
    if change is not None:
        stmt = stmt.where(AssetChangeEvent.change == change)

    rows = (
        await session.execute(
            stmt.order_by(AssetChangeEvent.observed_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()

    return envelope(
        [
            {
                "id": str(event.id),
                "change": event.change,
                "previous_value": event.previous_value,
                "current_value": event.current_value,
                "observed_at": event.observed_at.isoformat(),
                "scan_id": str(event.scan_id) if event.scan_id else None,
                "asset": {
                    "id": str(resource.id),
                    "name": resource.name,
                    "resource_type": resource.resource_type,
                    "environment": resource.environment,
                    # Whether it is currently missing, which is what turns a
                    # DISAPPEARED row from history into something to act on.
                    "absent_since": (
                        resource.absent_since.isoformat()
                        if resource.absent_since
                        else None
                    ),
                },
            }
            for event, resource in rows
        ],
        {"days": days, "limit": limit, "offset": offset},
    )
