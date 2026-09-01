"""The endpoint Azure calls when a customer's environment changes.

Unauthenticated in the session sense, necessarily: Event Grid delivers from
Microsoft's infrastructure and carries no CloudGuard user. What guards it is the
same HMAC-signed token the ARM template endpoint uses -- specific to one
connection, and useless for any other.

Everything here answers 200 wherever it can, and that is not laziness. Event
Grid retries a non-2xx for hours; retrying a delivery CloudGuard has
*deliberately* dropped would be load with no possible outcome. A bad token is
the exception, because that is not an event to drop but a caller with no
business here.

The work is deliberately not done in this request. Event Grid times the
response, and starting a scan behind it would put a queue, a database write and
a provider call between Azure and its acknowledgement.
"""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Query, Request, status
from fastapi.responses import JSONResponse

from app.core.db import service_session
from app.core.logging import get_logger
from app.core.signing import SignedStateError, verify_state
from app.services import change_events as service

router = APIRouter(prefix="/events", tags=["events"])

log = get_logger(__name__)

# How long a webhook token stays valid. Far longer than the consent round trip,
# because this one does not travel through a browser in the next ten minutes --
# it sits in the customer's Event Grid configuration and is used for as long as
# they leave it there.
#
# Bounded all the same. A credential with no expiry has no rotation story, and
# "regenerate the command" is a thing a customer can be asked to do once a year.
EVENT_TOKEN_TTL_SECONDS = 365 * 24 * 3600


@router.post("/azure/{connection_id}", include_in_schema=False)
async def azure_change_event(
    connection_id: UUID, request: Request, token: str = Query(default="")
) -> JSONResponse:
    """Accept an Event Grid delivery for one connection.

    Two kinds of request arrive here. The first is the validation handshake,
    which must echo a code back or the subscription never activates -- a
    customer whose ``az eventgrid`` command appeared to succeed would simply
    never be told about anything. The rest are resource changes.
    """
    if not _authorized(connection_id, token):
        # Deliberately the same answer whether the token is malformed, expired,
        # or signed for a different connection. This endpoint is reachable by
        # anyone, and distinguishing those would let a caller learn which
        # connection ids exist.
        return JSONResponse({"error": "Invalid token"}, status_code=400)

    events = await _payload(request)
    if events is None:
        return JSONResponse({"error": "Malformed event payload"}, status_code=400)

    for event in events:
        if service.is_validation(event):
            response = service.validation_response(event)
            if response is None:
                return JSONResponse(
                    {"error": "Validation event carried no code"}, status_code=400
                )
            log.info("events.validation_handshake", connection_id=str(connection_id))
            return JSONResponse(response, status_code=200)

    relevant = [event for event in events if service.is_relevant(event)]
    if not relevant:
        # Accepted and dropped. The alternative -- a non-2xx -- would have Azure
        # redelivering an event CloudGuard has already decided it cannot act on.
        return JSONResponse(
            {"accepted": len(events), "relevant": 0}, status_code=status.HTTP_200_OK
        )

    async with service_session() as session:
        connection = await service.connection_for_event(session, connection_id)
        if connection is None:
            # The connection is gone, or the customer turned this off. Either
            # way there is nothing to record and nothing for Azure to retry.
            return JSONResponse({"accepted": len(events), "relevant": 0}, status_code=200)

        await service.record_change(session, connection)
        await session.commit()

    log.info(
        "events.change_recorded",
        connection_id=str(connection_id),
        delivered=len(events),
        relevant=len(relevant),
    )
    return JSONResponse({"accepted": len(events), "relevant": len(relevant)}, status_code=200)


def _authorized(connection_id: UUID, token: str) -> bool:
    try:
        payload = verify_state(token, max_age_seconds=EVENT_TOKEN_TTL_SECONDS)
    except SignedStateError:
        return False
    if payload.get("purpose") != "event_grid":
        # A token minted for the ARM template must not open the webhook. They
        # are signed with the same secret, so the purpose is what separates
        # them.
        return False
    return str(connection_id) == payload.get("cloud_connection_id")


async def _payload(request: Request) -> list[dict[str, Any]] | None:
    """Event Grid posts an array. Anything else is not a delivery."""
    try:
        body = await request.json()
    except Exception:
        return None
    if isinstance(body, dict):
        # The CloudEvents schema delivers a single object. Accepted rather than
        # refused: which schema a subscription uses is the customer's choice in
        # the portal, and refusing one of the two would be a configuration
        # nobody could debug from the error.
        return [body]
    if isinstance(body, list) and all(isinstance(item, dict) for item in body):
        return body
    return None
