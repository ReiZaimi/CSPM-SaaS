"""Application registrations, and how long their secrets keep working.

The collector half of ``DECISIONS.md`` section 63: ``Application.Read.All`` has
been on the consent screen since onboarding existed, so this reading costs no
customer a redeploy or a second visit to a Global Administrator. What it
produces is a date, and a date is only a security fact once it is measured from
the moment of capture -- which is what these pin.
"""

from datetime import UTC, datetime, timedelta

from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Provider, ResourceType, RuleState
from app.rules.azure.identity.credentials import (
    AzureLongLivedApplicationCredentialRule,
)
from app.rules.base import RuleContext

CAPTURED = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
RULE = AzureLongLivedApplicationCredentialRule()


def snapshot(applications: list[dict], **kw) -> RawSnapshot:
    return RawSnapshot(
        provider=Provider.AZURE,
        tenant_id="tenant-1",
        subscription_id=None,
        collected_at=CAPTURED,
        data={"application_credentials": applications},
        **kw,
    )


def secret(days_out: float, kind: str = "passwordCredentials") -> dict:
    end = CAPTURED + timedelta(days=days_out)
    return {kind: [{"keyId": "k1", "displayName": "ci", "endDateTime": end.isoformat()}]}


def applications_in(state) -> list:
    return [r for r in state.resources if r.resource_type == ResourceType.APPLICATION]


def verdict(resource, errors: dict | None = None) -> RuleState:
    context = RuleContext(resources=[resource], collection_errors=errors or {})
    return RULE.evaluate(resource, context).state


# ------------------------------------------------------------- normalization
def test_a_registration_becomes_an_asset_with_its_credentials_dated() -> None:
    state = AzureNormalizer().normalize(
        snapshot([{"id": "a1", "appId": "app-1", "displayName": "pipeline", **secret(30)}])
    )

    app = applications_in(state)[0]
    assert app.provider_resource_id == "/applications/a1"
    assert app.name == "pipeline"
    assert app.metadata["credentials"][0]["kind"] == "secret"
    assert app.metadata["credentials"][0]["days_remaining"] == 30


def test_certificates_are_read_as_well_as_secrets() -> None:
    """Both are bearer credentials for the same application, and a rule that
    saw only one half would pass an application whose certificate outlives
    everybody who remembers issuing it."""
    state = AzureNormalizer().normalize(
        snapshot(
            [{"id": "a1", "displayName": "signer", **secret(900, "keyCredentials")}]
        )
    )

    credential = applications_in(state)[0].metadata["credentials"][0]
    assert credential["kind"] == "certificate"
    assert credential["days_remaining"] == 900


def test_an_age_is_measured_from_the_capture_and_not_from_now() -> None:
    """The property that keeps a replay honest.

    A rule is a deterministic function of the snapshot. If the days remaining
    were computed against the clock, re-evaluating a stored capture next year
    would reach a different verdict from the same evidence -- and "CloudGuard
    verified the fix" would mean nothing.
    """
    payload = snapshot([{"id": "a1", "displayName": "pipeline", **secret(400)}])
    first = applications_in(AzureNormalizer().normalize(payload))[0]

    replayed = RawSnapshot.from_json(payload.to_json())
    second = applications_in(AzureNormalizer().normalize(replayed))[0]

    assert replayed.collected_at == CAPTURED
    assert (
        first.metadata["credentials"][0]["days_remaining"]
        == second.metadata["credentials"][0]["days_remaining"]
        == 400
    )


def test_an_unreadable_expiry_is_not_an_expiry_of_zero() -> None:
    state = AzureNormalizer().normalize(
        snapshot([{"id": "a1", "displayName": "odd", "passwordCredentials": [
            {"keyId": "k1", "endDateTime": "whenever"}
        ]}])
    )

    credential = applications_in(state)[0].metadata["credentials"][0]
    assert credential["days_remaining"] is None
    assert credential["end_date"] is None


# --------------------------------------------------------------- the verdict
def test_a_secret_valid_for_years_fails() -> None:
    state = AzureNormalizer().normalize(
        snapshot([{"id": "a1", "displayName": "pipeline", **secret(700)}])
    )
    app = applications_in(state)[0]

    result = RULE.evaluate(app, RuleContext(resources=[app]))
    assert result.state is RuleState.FAIL
    assert "700 days" in (result.message or "")


def test_a_secret_inside_the_threshold_passes() -> None:
    state = AzureNormalizer().normalize(
        snapshot([{"id": "a1", "displayName": "pipeline", **secret(180)}])
    )
    assert verdict(applications_in(state)[0]) is RuleState.PASS


def test_an_already_expired_secret_is_not_a_finding() -> None:
    """An expired credential grants nobody anything. It is an application that
    has stopped working -- an outage rather than an exposure -- and reporting it
    here would fill a security tool with operational noise."""
    state = AzureNormalizer().normalize(
        snapshot([{"id": "a1", "displayName": "forgotten", **secret(-40)}])
    )
    assert verdict(applications_in(state)[0]) is RuleState.PASS


def test_an_application_with_no_credentials_is_out_of_scope() -> None:
    """A federated credential or a managed identity has no secret to leak,
    which is the recommended shape rather than an unchecked one."""
    state = AzureNormalizer().normalize(
        snapshot([{"id": "a1", "displayName": "federated"}])
    )
    assert verdict(applications_in(state)[0]) is RuleState.NOT_APPLICABLE


def test_a_credential_this_scan_could_not_read_is_unknown() -> None:
    state = AzureNormalizer().normalize(
        snapshot([{"id": "a1", "displayName": "odd", "passwordCredentials": [
            {"keyId": "k1", "endDateTime": "whenever"}
        ]}])
    )
    assert verdict(applications_in(state)[0]) is RuleState.UNKNOWN


def test_a_failed_listing_degrades_rather_than_passes() -> None:
    state = AzureNormalizer().normalize(
        snapshot([{"id": "a1", "displayName": "pipeline", **secret(30)}])
    )
    app = applications_in(state)[0]

    assert (
        verdict(app, {"application_credentials": "Access denied."}) is RuleState.UNKNOWN
    )
