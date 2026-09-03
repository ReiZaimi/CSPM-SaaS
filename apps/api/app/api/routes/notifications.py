from uuid import UUID

from fastapi import APIRouter, Query

from app.core.deps import DbSession, Tenant
from app.core.errors import NotFound, envelope
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


@router.delete("/{notification_id}")
async def dismiss_notification(
    notification_id: UUID, session: DbSession, tenant: Tenant
) -> dict:
    """Stop showing one notification to the person asking.

    A dismissal rather than a delete. What happened belongs to the organization
    and everybody in it reads the same rows, so removing one would be a reader
    deciding what their colleagues get told. DELETE all the same: from the
    caller's side the resource is their view of it, and that is what goes.

    No role check, for the reason ``/read`` has none: a VIEWER who cannot put
    down something they have already read would be shown it for ever.
    """
    dismissed = await service.dismiss(
        session, tenant.organization_id, tenant.user.id, notification_id
    )
    if not dismissed:
        raise NotFound()
    await session.commit()
    return envelope({"dismissed": str(notification_id)})


@router.delete("")
async def dismiss_all_notifications(session: DbSession, tenant: Tenant) -> dict:
    """Clear the panel for the person asking.

    Distinct from ``/read``, which moves a watermark and leaves everything in
    place. This is the reader saying they are done with what is there, and it
    says nothing about what arrives next.
    """
    count = await service.dismiss_all(session, tenant.organization_id, tenant.user.id)
    await session.commit()
    return envelope({"dismissed": count})
