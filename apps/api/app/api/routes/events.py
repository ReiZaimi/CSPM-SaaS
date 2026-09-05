"""The endpoint a cloud calls when a customer's environment changes.

Unauthenticated in the session sense, necessarily: the delivery comes from the
provider's infrastructure and carries no CloudGuard user. What guards it is the
same HMAC-signed token the artefact endpoint uses -- specific to one connection,
and useless for any other.

Everything here answers 200 wherever it can, and that is not laziness. Both
providers retry a non-2xx for hours; retrying a delivery CloudGuard has
*deliberately* dropped would be load with no possible outcome. A bad token is
the exception, because that is not an event to drop but a caller with no
business here.

The work is deliberately not done in this request. Delivery is timed, and
starting a scan behind it would put a queue, a database write and a provider
call between the cloud and its acknowledgement.

One route serves both clouds, and the provider is a path segment rather than a
lookup: the URL a customer already has wired into Event Grid ends
``/events/azure/<id>`` and keeps working unchanged.

**The two handshakes differ, and the difference has a security consequence.**
Event Grid asks for a code echoed in the response body. SNS hands over a URL and
activates when it is fetched -- an outbound request triggered by an inbound
payload, which is an SSRF unless the host is checked. The check belongs to the
provider that knows what its own hosts look like, so this endpoint fetches only
what the feed hands back and refuses everything else.
"""

from typing import Any
from uuid import UUID

import httpx
from fastapi import APIRouter, Query, Request, status
from fastapi.responses import JSONResponse

from app.core.db import service_session
from app.core.enums import Provider
from app.core.errors import NotConfigured
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


# How long to wait for an SNS confirmation fetch.
#
# Short on purpose. The subscription is activated by the *request arriving*, and
# a slow one must not hold the reply open past the delivery timeout -- SNS would
# then retry a confirmation that had already worked.
CONFIRM_TIMEOUT_SECONDS = 10.0


@router.post("/{provider}/{connection_id}", include_in_schema=False)
async def change_event(
    provider: str,
    connection_id: UUID,
    request: Request,
    token: str = Query(default=""),
) -> JSONResponse:
    """Accept one cloud's delivery for one connection.

    Two kinds of request arrive here. The first is the subscription handshake,
    without which the subscription exists and delivers nothing -- a customer
    whose wiring command appeared to succeed would simply never be told about
    anything. The rest are resource changes.
    """
    try:
        cloud = Provider(provider)
        service.is_validation({}, cloud)
    except (ValueError, NotConfigured):
        # An unknown provider, or one with no change feed. Refused rather than
        # dropped: this is not an event CloudGuard decided against, it is a URL
        # nothing should be posting to.
        return JSONResponse({"error": "Unknown provider"}, status_code=404)

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
        if service.is_validation(event, cloud):
            return await _handshake(event, cloud, connection_id)

    relevant = [event for event in events if service.is_relevant(event, cloud)]
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


async def _handshake(
    event: dict[str, Any], cloud: Provider, connection_id: UUID
) -> JSONResponse:
    """Activate the subscription, whichever way this cloud does it.

    Event Grid wants a code echoed in the body. SNS wants a URL fetched. A
    provider that answers neither has sent a handshake CloudGuard cannot
    complete, and saying so is better than a 200 that activates nothing.
    """
    response = service.validation_response(event, cloud)
    if response is not None:
        log.info(
            "events.validation_handshake",
            provider=cloud.value,
            connection_id=str(connection_id),
        )
        return JSONResponse(response, status_code=200)

    url = service.confirmation_url(event, cloud)
    if url is None:
        # Either no confirmation was carried, or it named a host this provider
        # does not vouch for. The second is the case that matters: fetching it
        # would make CloudGuard a request forwarder for whoever sent this.
        log.warning(
            "events.handshake_refused",
            provider=cloud.value,
            connection_id=str(connection_id),
        )
        return JSONResponse(
            {"error": "Subscription confirmation could not be completed"},
            status_code=400,
        )

    try:
        async with httpx.AsyncClient(timeout=CONFIRM_TIMEOUT_SECONDS) as client:
            await client.get(url)
    except Exception as exc:
        # 200 anyway. The subscription is not confirmed, and a retry is exactly
        # what should happen -- but SNS retries a confirmation on its own
        # schedule, and a non-2xx here buys nothing except a louder failure.
        log.warning(
            "events.confirmation_failed",
            provider=cloud.value,
            connection_id=str(connection_id),
            error=str(exc),
        )
        return JSONResponse({"confirmed": False}, status_code=200)

    log.info(
        "events.subscription_confirmed",
        provider=cloud.value,
        connection_id=str(connection_id),
    )
    return JSONResponse({"confirmed": True}, status_code=200)


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
