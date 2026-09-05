"""AWS's change feed, and the one place it differs dangerously from Azure's.

Event Grid confirms a subscription by asking for a code echoed in the response
body. SNS confirms by handing over a URL and activating when it is fetched --
an outbound request triggered by an inbound payload, from an endpoint anybody
holding the connection's token can reach. That is an SSRF unless the host is
checked, and the tests that matter most here are the ones that check it.

The rest is the same discipline the Azure feed follows: generous within the
sources CloudGuard judges, absolute outside them, and silent about reads --
scanning because somebody listed their buckets is a scan nothing asked for.
"""

import json

import pytest

from app.connectors.aws import change_events as feed
from app.connectors.registry import get_change_feed
from app.core.enums import Provider


def notification(**detail: object) -> dict:
    """An SNS envelope carrying an EventBridge event, as SNS delivers it."""
    return {
        "Type": "Notification",
        "TopicArn": "arn:aws:sns:eu-west-1:111122223333:cloudguard-change-events",
        "Message": json.dumps(
            {
                "source": "aws.s3",
                "detail-type": "AWS API Call via CloudTrail",
                "detail": {"eventName": "PutBucketPolicy", **detail},
            }
        ),
    }


def confirmation(url: str) -> dict:
    return {"Type": "SubscriptionConfirmation", "SubscribeURL": url}


# ------------------------------------------------------------ the SSRF guard
def test_only_an_sns_host_is_worth_fetching() -> None:
    """The endpoint is reachable by anyone with the connection's token.

    A confirmation URL taken on trust would make CloudGuard fetch whatever the
    caller named, including addresses only CloudGuard's own network can reach.
    """
    good = "https://sns.eu-west-1.amazonaws.com/?Action=ConfirmSubscription&Token=x"
    assert feed.confirmation_url(confirmation(good)) == good


@pytest.mark.parametrize(
    "url",
    [
        "https://169.254.169.254/latest/meta-data/",
        "https://internal.cloudguard.local/admin",
        "https://sns.eu-west-1.amazonaws.com.evil.test/",
        "https://evil.test/sns.eu-west-1.amazonaws.com",
        "https://sns.eu-west-1.amazonaws.com@evil.test/",
        "http://sns.eu-west-1.amazonaws.com/",
        "",
    ],
)
def test_anything_else_is_refused_rather_than_fetched(url: str) -> None:
    """Each of these is a way a host check gets written wrongly.

    A suffix test passes the third, a substring test passes the fourth, and
    userinfo before the host passes anything that splits on the wrong character.
    """
    assert feed.confirmation_url(confirmation(url)) is None


def test_the_china_partition_is_a_customer_too() -> None:
    url = "https://sns.cn-north-1.amazonaws.com.cn/?Action=ConfirmSubscription"
    assert feed.confirmation_url(confirmation(url)) == url


def test_sns_has_nothing_to_echo_in_the_reply() -> None:
    """``None`` is the complete answer, and the endpoint reads it as one: what
    activates the subscription is the fetch, not the body."""
    assert feed.validation_response(confirmation("https://sns.x.amazonaws.com/")) is None
    assert feed.is_validation(confirmation("https://sns.x.amazonaws.com/")) is True


# ----------------------------------------------------------- what is relevant
def test_a_write_to_a_watched_service_is_relevant() -> None:
    assert feed.is_relevant(notification()) is True


def test_a_read_is_not_a_change() -> None:
    """A scan started because somebody listed their buckets is a scan nothing
    asked for."""
    assert feed.is_relevant(notification(eventName="ListBuckets")) is False
    assert feed.is_relevant(notification(eventName="GetBucketPolicy")) is False


def test_a_failed_call_left_the_environment_as_it_was() -> None:
    """Scanning on one would be scanning because somebody lacked permission."""
    assert feed.is_relevant(notification(errorCode="AccessDenied")) is False


def test_a_service_no_rule_reads_cannot_change_a_verdict() -> None:
    event = {
        "Type": "Notification",
        "Message": json.dumps(
            {
                "source": "aws.cloudfront",
                "detail-type": "AWS API Call via CloudTrail",
                "detail": {"eventName": "CreateDistribution"},
            }
        ),
    }
    assert feed.is_relevant(event) is False


def test_a_scheduled_rule_is_not_an_api_call() -> None:
    event = {
        "Type": "Notification",
        "Message": json.dumps({"source": "aws.events", "detail-type": "Scheduled Event"}),
    }
    assert feed.is_relevant(event) is False


def test_a_malformed_message_is_dropped_rather_than_raised() -> None:
    """The endpoint answers 200 to everything it decides not to act on.

    An exception here would turn that into a non-2xx, and SNS would redeliver
    the same unparseable payload for hours.
    """
    assert feed.is_relevant({"Type": "Notification", "Message": "not json"}) is False
    assert feed.is_relevant({"Type": "Notification"}) is False
    assert feed.is_relevant({}) is False


def test_a_confirmation_is_not_a_change() -> None:
    assert feed.is_relevant(confirmation("https://sns.x.amazonaws.com/")) is False


# --------------------------------------------------------------- the wiring
def test_the_command_carries_this_connection_s_own_endpoint() -> None:
    """Generated rather than documented, for the reason the stack is: the URL
    carries a signed token specific to one connection."""
    command = feed.subscription_command(
        "111122223333", "https://api.example.com/api/v1/events/aws/abc?token=xyz"
    )

    assert "https://api.example.com/api/v1/events/aws/abc?token=xyz" in command
    assert "111122223333" in command
    assert "aws sns subscribe" in command
    assert "aws events put-rule" in command


def test_the_rule_filters_at_the_source_as_well() -> None:
    """The endpoint drops what it cannot use anyway, but a filter AWS applies is
    traffic that never leaves the customer's account."""
    command = feed.subscription_command("111122223333", "https://x/y")

    assert "aws.s3" in command
    assert "AWS API Call via CloudTrail" in command


# ------------------------------------------------------------- the seam
def test_the_registry_hands_back_the_aws_feed() -> None:
    """Asked before any connection is resolved: a delivery arrives before
    CloudGuard knows whose it is, so deciding whether it is worth reading must
    not need credentials to the environment it is about."""
    assert get_change_feed(Provider.AWS) is feed


def test_both_feeds_answer_the_same_questions() -> None:
    """The contract, checked rather than assumed.

    A feed missing one of these fails at the moment a customer's environment
    changes, which is the worst time to discover it.
    """
    from app.connectors.registry import CHANGE_FEEDS

    for provider, module in CHANGE_FEEDS.items():
        for name in (
            "is_validation",
            "validation_response",
            "confirmation_url",
            "is_relevant",
            "subscription_command",
        ):
            assert hasattr(module, name), f"{provider.value} feed has no {name}"
