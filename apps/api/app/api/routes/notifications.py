
from fastapi import APIRouter, Query

from app.core.deps import DbSession, Tenant
from app.core.errors import envelope
from app.schemas.notification import NotificationOut
from app.services import notifications as service

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("")
async def list_notifications(
    session: DbSession,
    tenant: Tenant,
    limit: int = Query(default=20, le=50),
) -> dict:
    """What happened that this person has not seen.

    Deliberately not ``/changes``. That answers "what moved in the environment"
    and is a property of the estate; this answers "what happened since you last
    looked" and is a property of a reader -- so the same scan produces the same
    changes for everyone and a different unread count for each of them.

    The list and the count come from one read of the same rows. Counting in a
    second query would let a badge say three above a panel showing two, which is
    the kind of disagreement people stop trusting a whole feature over.
    """
    rows, unread = await service.unread_for(
        session, tenant.organization_id, tenant.user.id, limit=limit
    )
    return envelope(
        [NotificationOut.model_validate(row).model_dump(mode="json") for row in rows],
        {"unread": unread, "total": len(rows)},
    )


@router.post("/read")
async def mark_read(session: DbSession, tenant: Tenant) -> dict:
    """Move this person's watermark to now.

    A watermark rather than a flag per row, because the question has one answer
    and one timestamp -- and per-row read state would make the badge a number
    about somebody's habits rather than about their estate.

    No role check: reading is not a privilege, and a VIEWER who cannot dismiss
    what they have already read would be shown the same news for ever.
    """
    read_through = await service.mark_read(
        session, tenant.organization_id, tenant.user.id
    )
    await session.commit()
    return envelope({"read_through": read_through.isoformat()})
