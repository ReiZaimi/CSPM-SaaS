"""Reacting to a change in the customer's environment, without reacting to each one.

A schedule promises how stale the picture may get. It does not promise the
picture is right: a subscription read nightly is wrong from the moment somebody
opens a security group at nine in the morning until the scan at three the next.

Azure will say when something changed, through an Event Grid subscription on the
customer's own subscription. Three things have to be true for that to be worth
having, and each is a decision here rather than a detail.

**CloudGuard cannot create the subscription.** Creating one is a write in the
customer's tenant, and holding no write permission at all is the strongest
security claim this product makes. So the customer creates it, from a command
CloudGuard generates -- the same shape as the scanner role deployment, and for
the same reason.

**Most events are not about security.** ARM reports every write in the
subscription, including the ones a deployment makes to things no rule judges. An
event that cannot change a verdict must not cost a scan.

**One deployment is one change, not forty.** A template deployment emits dozens
of events in a minute. Scanning on each would turn a helpful signal into a
denial of service against the customer's own API limits -- so a burst marks the
connection and the scan waits for quiet.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.cloud_connection import CloudConnection

log = get_logger(__name__)

# Event Grid's handshake. A subscription is not active until the endpoint echoes
# the code back, so this is not optional politeness -- without it the customer's
# `az eventgrid` command appears to succeed and delivers nothing.
VALIDATION_EVENT = "Microsoft.EventGrid.SubscriptionValidationEvent"

# The ARM events worth listening to. Reads are absent because they are not
# changes, and failures are absent because a write that failed left the
# environment as it was -- scanning on one would be scanning because somebody
# lacked permission.
CHANGE_EVENT_TYPES = frozenset(
    {
        "Microsoft.Resources.ResourceWriteSuccess",
        "Microsoft.Resources.ResourceDeleteSuccess",
        "Microsoft.Resources.ResourceActionSuccess",
    }
)

# Resource providers CloudGuard actually judges. An event outside them cannot
# change any verdict, so it is acknowledged and dropped.
#
# Derived from what the rules read rather than from what Azure emits: adding a
# provider here without a rule that reads it would buy scans nothing looks at,
# and a test keeps this honest against the collection plan.
WATCHED_PROVIDERS = frozenset(
    {
        "microsoft.storage",
        "microsoft.network",
        "microsoft.compute",
        "microsoft.sql",
        "microsoft.dbforpostgresql",
        "microsoft.authorization",
        "microsoft.insights",
    }
)

# How long the environment has to be quiet before the change is worth reading.
# Long enough that a template deployment lands as one scan, short enough that a
# customer who opened a port sees the finding while they are still looking at
# the screen.
QUIET_PERIOD = timedelta(minutes=3)

# And the floor between change-triggered scans of one connection. A team
# deploying all afternoon would otherwise be scanned every three minutes, which
# is the storm the quiet period was meant to prevent, arriving more slowly.
MIN_INTERVAL = timedelta(minutes=30)


def is_validation(event: dict[str, Any]) -> bool:
    return str(event.get("eventType", "")) == VALIDATION_EVENT


def validation_response(event: dict[str, Any]) -> dict[str, str] | None:
    """The echo Event Grid needs before it will deliver anything.

    Returns ``None`` where the code is missing, which is not a handshake to
    answer: replying with an empty code would activate nothing and hide the
    reason.
    """
    code = (event.get("data") or {}).get("validationCode")
    return {"validationResponse": str(code)} if code else None


def is_relevant(event: dict[str, Any]) -> bool:
    """Whether this event could change a verdict.

    Deliberately generous within the providers CloudGuard judges and absolute
    outside them. Working out whether *this particular* write changed something
    a rule reads would mean reimplementing the rules against an event payload
    that carries an operation name and no state -- and being wrong in the
    direction of not scanning is how a customer's open port stays open.
    """
    if str(event.get("eventType", "")) not in CHANGE_EVENT_TYPES:
        return False

    operation = str((event.get("data") or {}).get("operationName", ""))
    provider = operation.split("/", 1)[0].strip().lower()
    if provider not in WATCHED_PROVIDERS:
        return False

    # ARM spells a read `.../read`. A success event for one should not exist,
    # but an endpoint that trusts that would be trusting somebody else's
    # invariant.
    return not operation.lower().endswith("/read")


async def record_change(
    session: AsyncSession,
    connection: CloudConnection,
    *,
    now: datetime | None = None,
) -> None:
    """Mark the connection as having changed, without starting anything.

    The scan is started by the sweep, once the environment has gone quiet. This
    is deliberately the whole of what a webhook does: it runs inside a request
    Azure is timing, and starting work here would put a queue, a database write
    and a provider call between Event Grid and its 200.
    """
    moment = now or datetime.now(UTC)
    if connection.change_pending_since is None:
        connection.change_pending_since = moment
    connection.last_change_event_at = moment


async def connections_ready(
    session: AsyncSession, *, now: datetime | None = None, limit: int = 20
) -> list[CloudConnection]:
    """Connections whose burst of changes has settled.

    Quiet for :data:`QUIET_PERIOD` since the last event, and not scanned for a
    change within :data:`MIN_INTERVAL`. The second condition is what keeps an
    afternoon of deployments from becoming an afternoon of scans.
    """
    moment = now or datetime.now(UTC)
    rows = (
        (
            await session.execute(
                select(CloudConnection)
                .where(
                    CloudConnection.change_events_enabled.is_(True),
                    CloudConnection.change_pending_since.is_not(None),
                    CloudConnection.last_change_event_at <= moment - QUIET_PERIOD,
                )
                .order_by(CloudConnection.change_pending_since)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


def clear_pending(connection: CloudConnection) -> None:
    """The burst has been acted on. The next event starts a new one."""
    connection.change_pending_since = None


def event_subscription_command(subscription_id: str, endpoint: str) -> str:
    """The command the customer runs to wire their subscription to CloudGuard.

    Generated rather than documented, for the reason the scanner role's template
    is generated: the endpoint carries a signed token specific to this
    connection, and a customer copying a URL out of a documentation page would
    be copying somebody else's.

    Filtered at the source as well as at the endpoint. The endpoint drops what
    it cannot use anyway, but a filter Azure applies is traffic that never
    leaves the customer's tenant -- cheaper for them, and a smaller surface for
    CloudGuard to be wrong about.
    """
    included = " ".join(sorted(CHANGE_EVENT_TYPES))
    return (
        "az eventgrid event-subscription create "
        "--name cloudguard-change-events "
        f"--source-resource-id /subscriptions/{subscription_id} "
        f"--endpoint {endpoint} "
        f"--included-event-types {included} "
        "--endpoint-type webhook"
    )


async def connection_for_event(
    session: AsyncSession, connection_id: UUID
) -> CloudConnection | None:
    """The connection an event names, if it is one that asked for events.

    A connection with the feature off is treated exactly as one that does not
    exist. Otherwise turning the feature off would leave a webhook that keeps
    accepting -- and quietly resuming when somebody turned it back on.
    """
    connection = await session.get(CloudConnection, connection_id)
    if connection is None or not connection.change_events_enabled:
        return None
    return connection
