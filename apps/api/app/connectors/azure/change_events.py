"""Azure's change feed: what Event Grid says, and what is worth acting on.

The provider-specific half of change-triggered scanning. The debounce -- how
long to wait for a burst to settle, how often a connection may be scanned for a
change -- is neutral and lives in ``app/services/change_events.py``. What
belongs here is everything spelled in Azure's own vocabulary: the handshake it
requires, the event types it emits, the resource providers whose writes could
change a verdict, and the command a customer runs to wire it up.

Behind the connector seam, because a services module hard-coding
``Microsoft.Storage`` would make "everything above this line is
provider-neutral" false in exactly the way importing Azure's evidence keys into
the pipeline did.
"""

from typing import Any

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
# provider here without a rule that reads it would buy scans nothing looks at.
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


def is_validation(event: dict[str, Any]) -> bool:
    return str(event.get("eventType", "")) == VALIDATION_EVENT


def validation_response(event: dict[str, Any]) -> dict[str, str] | None:
    """The echo Event Grid needs before it will deliver anything.

    ``None`` where the code is missing, which is not a handshake to answer:
    replying with an empty code would activate nothing and hide the reason.
    """
    code = (event.get("data") or {}).get("validationCode")
    return {"validationResponse": str(code)} if code else None


def confirmation_url(event: dict[str, Any]) -> str | None:
    """Nothing to fetch. Event Grid confirms in the response body.

    ``None`` is a complete answer rather than a failure. SNS activates a
    subscription by handing over a URL to fetch, and this exists so the endpoint
    can serve both without knowing which cloud it is answering.
    """
    return None


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


def subscription_command(scope_id: str, endpoint: str) -> str:
    """The command the customer runs to wire one subscription to CloudGuard.

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
        f"--source-resource-id /subscriptions/{scope_id} "
        f"--endpoint {endpoint} "
        f"--included-event-types {included} "
        "--endpoint-type webhook"
    )
