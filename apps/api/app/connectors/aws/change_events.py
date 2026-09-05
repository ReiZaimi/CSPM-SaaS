"""AWS's change feed: what EventBridge says, and what is worth acting on.

The provider-specific half of change-triggered scanning, the sibling of
``azure/change_events.py``. The debounce -- how long to wait for a burst to
settle, how often a connection may be scanned for a change -- is neutral and
lives in ``app/services/change_events.py``.

**The delivery path is EventBridge -> SNS -> HTTPS**, not EventBridge on its own.
EventBridge cannot post to an arbitrary HTTPS endpoint without an API
destination, and an API destination needs the customer to create a connection
holding a credential, then a destination, then a rule -- three resources and a
secret in their account. An SNS topic with an HTTPS subscription is one more
command than the Azure equivalent and stores nothing of ours.

That costs one thing Azure does not have: **SNS confirms a subscription by
handing over a URL to fetch**, rather than by asking for a code echoed in the
response body. So the feed exposes :func:`confirmation_url`, and the endpoint
fetches it. That is an outbound request triggered by an inbound payload, which
is an SSRF if the host is taken on trust -- so it is not. Only AWS's own SNS
hosts are accepted, and anything else is refused rather than fetched.

.. warning::

   Nothing here has been run against a live AWS account. The event shapes come
   from the published reference; ``docs/AWS_INTEGRATION.md`` §1 is the checklist.
"""

import json
import re
from typing import Any

# SNS's own message types. ``SubscriptionConfirmation`` is the handshake: until
# the URL inside it is fetched, the subscription exists and delivers nothing --
# a customer whose ``aws sns subscribe`` appeared to succeed would simply never
# be told about anything.
CONFIRMATION_TYPE = "SubscriptionConfirmation"
NOTIFICATION_TYPE = "Notification"

# Hosts a confirmation URL may point at.
#
# This is the whole SSRF guard, and it is why the URL is validated here rather
# than fetched by whoever received it. The endpoint is reachable by anyone
# holding the connection's token; a payload naming an internal address would
# otherwise turn CloudGuard into a request forwarder into its own network.
#
# ``amazonaws.com.cn`` is included because the China partitions use it and a
# customer there is not a customer to break; every other suffix is refused.
SNS_HOST = re.compile(
    r"^sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$", re.IGNORECASE
)

# EventBridge sources CloudGuard actually judges. An event outside them cannot
# change any verdict, so it is acknowledged and dropped.
#
# Derived from what the rules read rather than from what AWS emits: adding a
# source here without a rule that reads it would buy scans nothing looks at.
WATCHED_SOURCES = frozenset(
    {
        "aws.s3",
        "aws.ec2",
        "aws.rds",
        "aws.iam",
        "aws.kms",
        "aws.cloudtrail",
        "aws.config",
        "aws.guardduty",
        "aws.accessanalyzer",
    }
)

# What a CloudTrail-backed EventBridge event calls itself. Everything else --
# scheduled rules, service health, custom buses -- is not a change to an
# environment and is dropped.
API_CALL_DETAIL_TYPE = "AWS API Call via CloudTrail"

# Read-only CloudTrail events. AWS names them consistently enough for a prefix
# test to be worth having: a scan started because somebody listed their buckets
# is a scan nothing asked for.
READ_PREFIXES = ("Get", "List", "Describe", "Head", "Lookup", "Batch Get")


def is_validation(event: dict[str, Any]) -> bool:
    return str(event.get("Type", "")) == CONFIRMATION_TYPE


def validation_response(event: dict[str, Any]) -> dict[str, str] | None:
    """Nothing to echo. SNS confirms out of band.

    ``None`` here is a complete answer rather than a failure, and the endpoint
    reads it as one: what activates an SNS subscription is a fetch of
    :func:`confirmation_url`, not a body in the reply.
    """
    return None


def confirmation_url(event: dict[str, Any]) -> str | None:
    """The URL that activates this subscription, if it is safe to fetch.

    ``None`` for a payload whose ``SubscribeURL`` is missing or points anywhere
    but an AWS SNS host. Refusing is the right answer to both: the endpoint is
    reachable by anyone holding the connection's token, and a URL taken on trust
    would make CloudGuard fetch whatever an attacker named -- including
    addresses only CloudGuard's own network can reach.
    """
    url = str(event.get("SubscribeURL") or "")
    if not url.startswith("https://"):
        return None
    host = url.removeprefix("https://").split("/", 1)[0].split(":", 1)[0]
    return url if SNS_HOST.fullmatch(host) else None


def is_relevant(event: dict[str, Any]) -> bool:
    """Whether this delivery could change a verdict.

    Deliberately generous within the sources CloudGuard judges and absolute
    outside them. Working out whether *this particular* write changed something
    a rule reads would mean reimplementing the rules against an event payload
    that carries an API name and no state -- and being wrong in the direction of
    not scanning is how a customer's open port stays open.
    """
    if str(event.get("Type", "")) != NOTIFICATION_TYPE:
        return False

    detail = _eventbridge(event)
    if detail is None:
        return False
    if str(detail.get("detail-type", "")) != API_CALL_DETAIL_TYPE:
        return False
    if str(detail.get("source", "")).lower() not in WATCHED_SOURCES:
        return False

    name = str((detail.get("detail") or {}).get("eventName", ""))
    if name.startswith(READ_PREFIXES):
        return False
    # A call that failed left the environment as it was, so scanning on one
    # would be scanning because somebody lacked permission.
    return not (detail.get("detail") or {}).get("errorCode")


def _eventbridge(event: dict[str, Any]) -> dict[str, Any] | None:
    """The EventBridge event inside an SNS envelope.

    SNS carries it as a JSON *string* in ``Message``, so this is a parse rather
    than a lookup -- and a malformed one is dropped rather than raised: the
    endpoint answers 200 to everything it has decided not to act on, and an
    exception here would turn that into hours of SNS retries.
    """
    raw = event.get("Message")
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def subscription_command(scope_id: str, endpoint: str) -> str:
    """What the customer runs to wire one account to CloudGuard.

    Generated rather than documented, for the reason the scanner stack is
    generated: the endpoint carries a signed token specific to this connection,
    and a customer copying a URL out of a documentation page would be copying
    somebody else's.

    Three commands rather than Azure's one, because AWS has no single call that
    points a rule at an HTTPS endpoint. The topic is the customer's, in their
    account, and CloudGuard holds no permission over it -- which is the same
    trade as the Event Grid subscription: CloudGuard generates the command and
    the customer runs it, because creating any of this is a *write*.

    Filtered at the source as well as at the endpoint. The endpoint drops what
    it cannot use anyway, but a filter AWS applies is traffic that never leaves
    the customer's account.
    """
    pattern = json.dumps(
        {"source": sorted(WATCHED_SOURCES), "detail-type": [API_CALL_DETAIL_TYPE]}
    )
    # The region stays a placeholder and the account does not. CloudGuard knows
    # which account this connection covers; which region the customer wants the
    # topic in is theirs to choose, and guessing would put it somewhere they did
    # not ask for.
    account = scope_id or "<account-id>"
    topic = f"arn:aws:sns:<region>:{account}:cloudguard-change-events"
    return (
        "# 1. A topic in your account. CloudGuard never touches it.\n"
        "aws sns create-topic --name cloudguard-change-events\n\n"
        "# 2. Deliver it to CloudGuard. The URL carries a token for this "
        "connection only.\n"
        "aws sns subscribe --protocol https "
        f"--topic-arn {topic} "
        f"--notification-endpoint '{endpoint}'\n\n"
        "# 3. Send the changes CloudGuard judges, and nothing else.\n"
        "aws events put-rule --name cloudguard-change-events "
        f"--event-pattern '{pattern}'\n"
        "aws events put-targets --rule cloudguard-change-events "
        f"--targets Id=1,Arn={topic}"
    )
