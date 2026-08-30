"""Reacting to a change in the customer's environment, without reacting to each one.

A schedule promises how stale the picture may get. It does not promise the
picture is right: a subscription read nightly is wrong from the moment somebody
opens a security group at nine in the morning until the scan at three the next.

A provider will say when something changed -- Azure through an Event Grid
subscription on the customer's own subscription. What that looks like is the
provider's business and lives beside its connector; what lives here is the part
that is the same whichever cloud it is. Three things have to be true for any of
it to be worth having, and each is a decision here rather than a detail.

**CloudGuard cannot create the subscription.** Creating one is a write in the
customer's tenant, and holding no write permission at all is the strongest
security claim this product makes. So the customer creates it, from a command
CloudGuard generates -- the same shape as the scanner role deployment, and for
the same reason.

**Most events are not about security.** A cloud reports every write, including
the ones a deployment makes to things no rule judges. An event that cannot
change a verdict must not cost a scan -- and deciding which those are needs that
cloud's own vocabulary, so it is asked of the provider rather than answered
here.

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

from app.connectors.registry import get_change_feed
from app.core.enums import Provider
from app.core.logging import get_logger
from app.models.cloud_connection import CloudConnection

log = get_logger(__name__)

# How long the environment has to be quiet before the change is worth reading.
# Long enough that a template deployment lands as one scan, short enough that a
# customer who opened a port sees the finding while they are still looking at
# the screen.
QUIET_PERIOD = timedelta(minutes=3)

# And the floor between change-triggered scans of one connection. A team
# deploying all afternoon would otherwise be scanned every three minutes, which
# is the storm the quiet period was meant to prevent, arriving more slowly.
MIN_INTERVAL = timedelta(minutes=30)


def is_validation(event: dict[str, Any], provider: Provider = Provider.AZURE) -> bool:
    return bool(get_change_feed(provider).is_validation(event))


def validation_response(
    event: dict[str, Any], provider: Provider = Provider.AZURE
) -> dict[str, str] | None:
    response: dict[str, str] | None = get_change_feed(provider).validation_response(event)
    return response


def is_relevant(event: dict[str, Any], provider: Provider = Provider.AZURE) -> bool:
    return bool(get_change_feed(provider).is_relevant(event))


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


def event_subscription_command(
    scope_id: str, endpoint: str, provider: Provider = Provider.AZURE
) -> str:
    """What the customer runs to wire one scanned unit to CloudGuard."""
    return str(get_change_feed(provider).subscription_command(scope_id, endpoint))


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
