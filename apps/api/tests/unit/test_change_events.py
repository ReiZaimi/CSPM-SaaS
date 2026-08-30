"""Reacting to a change without reacting to each one.

Three things decide whether an Event Grid path is worth having, and each is a
way for it to be actively harmful if wrong.

The **handshake** must be answered or the subscription never activates -- a
customer whose `az eventgrid` command appeared to succeed would simply never be
told about anything, which is worse than not offering the feature.

The **filter** must drop what cannot change a verdict. ARM reports every write
in a subscription, and a scan per tag edit is a denial of service against the
customer's own API limits, paid for by them.

The **debounce** must collapse a deployment into one reading. Forty events in a
minute is one change; treating it as forty is the same storm the filter was
meant to prevent, arriving from a different direction.
"""

from datetime import UTC, datetime, timedelta

from app.services import change_events as service


def change(operation: str, event_type: str = "Microsoft.Resources.ResourceWriteSuccess") -> dict:
    return {"eventType": event_type, "data": {"operationName": operation}}


class Connection:
    """Only the three columns the debounce touches."""

    def __init__(self) -> None:
        self.change_pending_since: datetime | None = None
        self.last_change_event_at: datetime | None = None


# ----------------------------------------------------------------- handshake
def test_the_validation_code_is_echoed_back() -> None:
    """Not optional politeness. Without it Event Grid activates nothing."""
    event = {
        "eventType": service.VALIDATION_EVENT,
        "data": {"validationCode": "512d38b6-c7b8-40c8-89fe-f46f9e9622b6"},
    }

    assert service.is_validation(event)
    assert service.validation_response(event) == {
        "validationResponse": "512d38b6-c7b8-40c8-89fe-f46f9e9622b6"
    }


def test_a_validation_event_with_no_code_is_not_answered() -> None:
    """Replying with an empty code would activate nothing and hide the reason."""
    assert service.validation_response({"eventType": service.VALIDATION_EVENT, "data": {}}) is None


# -------------------------------------------------------------------- filter
def test_a_write_to_something_a_rule_reads_is_relevant() -> None:
    assert service.is_relevant(change("Microsoft.Network/networkSecurityGroups/write"))
    assert service.is_relevant(change("Microsoft.Storage/storageAccounts/write"))
    assert service.is_relevant(
        change("Microsoft.Authorization/roleAssignments/write")
    )


def test_a_deletion_is_a_change_too() -> None:
    """An asset that has gone is a posture that has changed -- and the scan is
    what turns that into a DISAPPEARED event rather than a stale inventory."""
    assert service.is_relevant(
        change(
            "Microsoft.Storage/storageAccounts/delete",
            "Microsoft.Resources.ResourceDeleteSuccess",
        )
    )


def test_a_write_to_something_no_rule_reads_is_dropped() -> None:
    """The customer's own web app deployments are not a security event, and a
    scan each would be their API limits spent on nothing."""
    assert not service.is_relevant(change("Microsoft.Web/sites/write"))
    assert not service.is_relevant(change("Microsoft.ContainerRegistry/registries/write"))


def test_a_failed_write_is_not_a_change() -> None:
    """It left the environment as it was. Scanning would be scanning because
    somebody lacked permission."""
    assert not service.is_relevant(
        change(
            "Microsoft.Network/networkSecurityGroups/write",
            "Microsoft.Resources.ResourceWriteFailure",
        )
    )


def test_a_read_is_not_a_change() -> None:
    assert not service.is_relevant(change("Microsoft.Storage/storageAccounts/read"))


def test_an_event_with_no_operation_is_dropped() -> None:
    """Rather than treated as a change of unknown kind: an endpoint anyone can
    post to must not turn an empty body into a scan."""
    assert not service.is_relevant({"eventType": "Microsoft.Resources.ResourceWriteSuccess"})


# ------------------------------------------------------------------ debounce
async def test_the_first_event_of_a_burst_starts_the_clock() -> None:
    connection = Connection()
    now = datetime(2026, 8, 31, 9, 0, tzinfo=UTC)

    await service.record_change(None, connection, now=now)  # type: ignore[arg-type]

    assert connection.change_pending_since == now
    assert connection.last_change_event_at == now


async def test_later_events_move_the_quiet_clock_but_not_the_start() -> None:
    """The two timestamps answer different halves. Without the first, a scan
    started after the quiet period would not know how long the environment had
    been drifting -- only that it had stopped."""
    connection = Connection()
    start = datetime(2026, 8, 31, 9, 0, tzinfo=UTC)

    await service.record_change(None, connection, now=start)  # type: ignore[arg-type]
    for minute in (1, 2, 3):
        await service.record_change(  # type: ignore[arg-type]
            None, connection, now=start + timedelta(minutes=minute)
        )

    assert connection.change_pending_since == start
    assert connection.last_change_event_at == start + timedelta(minutes=3)


def test_acting_on_a_burst_clears_it_so_the_next_one_is_separate() -> None:
    connection = Connection()
    connection.change_pending_since = datetime(2026, 8, 31, 9, 0, tzinfo=UTC)

    service.clear_pending(connection)

    assert connection.change_pending_since is None


def test_the_quiet_period_is_long_enough_for_a_deployment_and_no_longer() -> None:
    """A judgement, pinned so it cannot drift by accident. Under a minute and a
    template deployment becomes several scans; over ten and a customer who just
    opened a port has stopped looking at the screen."""
    assert timedelta(minutes=1) <= service.QUIET_PERIOD <= timedelta(minutes=10)
    assert service.MIN_INTERVAL > service.QUIET_PERIOD


# ------------------------------------------------------------------- command
def test_the_command_names_this_connection_and_nothing_else() -> None:
    """Generated rather than documented: the endpoint carries a signed token
    specific to one connection, and a customer copying a URL out of a
    documentation page would be copying somebody else's."""
    command = service.event_subscription_command(
        "00000000-0000-0000-0000-000000000001",
        "https://api.example.com/api/v1/events/azure/abc?token=signed.mac",
    )

    assert "--source-resource-id /subscriptions/00000000-0000-0000-0000-000000000001" in command
    assert "token=signed.mac" in command
    # Filtered at the source as well as at the endpoint: traffic Azure drops
    # never leaves the customer's tenant.
    assert "--included-event-types" in command
    for event_type in service.CHANGE_EVENT_TYPES:
        assert event_type in command
