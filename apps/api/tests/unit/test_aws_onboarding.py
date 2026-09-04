"""Connecting an AWS account: one grant, and the id that guards it.

The flow differs from Azure's in exactly one structural way and everything else
follows: there is no consent step. The customer deploys a stack, and the role it
creates is the whole grant. So a connection must not sit waiting for a consent
that is never coming, and one successful assume-role has to record both columns
Azure fills separately.

The external id is the part with a security consequence. It is generated
server-side when the connection is created, and a role must never be assumed
without one.
"""

import uuid
from typing import Any

import pytest

from app.connectors.aws.auth import RoleAssumer, new_external_id
from app.connectors.aws.onboarding import AwsOnboarding
from app.connectors.registry import get_onboarding
from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
    Provider,
)
from app.core.errors import NotConfigured, ValidationFailed
from app.models.cloud_connection import CloudConnection

ACCOUNT = "111122223333"


def connection(**kwargs: Any) -> CloudConnection:
    defaults: dict = {
        "provider": Provider.AWS,
        "name": "Production",
        "scope_type": ConnectionScope.ORGANIZATION,
        "scope_id": ACCOUNT,
        "consent_status": ConsentStatus.PENDING,
        "status": CloudAccountStatus.PENDING,
        "role_version": "v1",
    }
    built = CloudConnection(**{**defaults, **kwargs})
    built.id = uuid.uuid4()
    if built.provider_ref is None:
        built.provider_ref = {}
    return built


def ready(**kwargs: Any) -> CloudConnection:
    built = connection(**kwargs)
    built.provider_ref = AwsOnboarding().initial_provider_ref(built)
    return built


# ------------------------------------------------------------- the flow shape
def test_aws_has_no_consent_step_to_wait_for() -> None:
    """A connection with no consent step must not sit forever waiting for one.

    Azure's polling loop refuses to probe until consent has reported the tenant,
    which is right for Azure and would leave every AWS connection permanently
    PENDING.
    """
    assert AwsOnboarding().has_separate_consent is False
    assert AwsOnboarding().start_url(connection()) == (None, None)


def test_every_scope_names_an_account_including_the_widest() -> None:
    """Azure's tenant root needs no id because consent reports the tenant.

    AWS has nothing equivalent: there is no call CloudGuard can make until it
    knows an account to assume a role in.
    """
    onboarding = AwsOnboarding()
    for scope in (
        ConnectionScope.ORGANIZATION,
        ConnectionScope.ORGANIZATIONAL_UNIT,
        ConnectionScope.ACCOUNT,
    ):
        assert onboarding.requires_scope_id(scope) is True


def test_the_registry_hands_back_aws_rather_than_azure() -> None:
    """Sending an AWS customer to a Microsoft consent screen is the failure this
    prevents."""
    assert isinstance(get_onboarding(Provider.AWS), AwsOnboarding)


# ------------------------------------------------------------ the external id
def test_a_connection_is_born_with_an_external_id() -> None:
    """Generated before anything can name it, so the template and the trust
    policy cannot disagree about what it is."""
    reference = AwsOnboarding().initial_provider_ref(connection())

    assert reference["external_id"].startswith("cg-")
    assert len(reference["external_id"]) > 24
    assert reference["role_arn"] == f"arn:aws:iam::{ACCOUNT}:role/CloudGuardScannerRole"


def test_two_connections_never_share_an_external_id() -> None:
    """Per customer and unguessable, or it guards nothing."""
    assert new_external_id() != new_external_id()


def test_a_role_is_never_assumed_without_one() -> None:
    """An assume-role call with no external id succeeds against a role whose
    trust policy does not require one -- which is exactly the misconfiguration
    CloudGuard must not participate in."""
    with pytest.raises(NotConfigured):
        RoleAssumer("arn:aws:iam::1:role/x", "")


def test_no_role_arn_is_refused_rather_than_guessed() -> None:
    with pytest.raises(NotConfigured):
        RoleAssumer("", "cg-something")


# ------------------------------------------------------------- the artefact
def test_the_stack_is_ready_as_soon_as_the_connection_exists() -> None:
    """Azure's template waits for a service principal consent has to publish.

    AWS's waits for nothing: the identity the trust policy names is
    CloudGuard's own and was known before the customer arrived.
    """
    assert AwsOnboarding().artifact_ready(ready()) is True


def test_no_external_id_means_nothing_safe_to_deploy() -> None:
    with pytest.raises(ValidationFailed, match="external id"):
        AwsOnboarding().artifact(connection())


def test_the_artefact_is_named_as_a_cloudformation_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.core.config.settings.aws_principal_arn", "arn:aws:iam::9:user/cg")

    artifact = AwsOnboarding().artifact(ready())

    assert artifact.filename.endswith(".template.json")
    assert '"AWSTemplateFormatVersion"' in artifact.body


# -------------------------------------------------------------- discovery
async def test_a_single_account_connection_discovers_itself() -> None:
    """Not a special case so much as the honest answer for a boundary of one."""
    found = await AwsOnboarding().discover(
        ready(scope_type=ConnectionScope.ACCOUNT, scope_id=ACCOUNT)
    )

    assert [a.account_id for a in found] == [ACCOUNT]
    assert found[0].provider_ref["role_arn"].endswith(f"{ACCOUNT}:role/CloudGuardScannerRole")


async def test_an_organization_gives_each_account_its_own_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One stack deployed everywhere, so the ARNs differ only by account id.

    The external id is shared, and correctly: it identifies the *relationship*,
    not the account.

    A suspended account is dropped rather than scanned. Every listing in one
    fails for a reason the customer already knows about, and reporting that as
    a coverage gap would be CloudGuard inventing a problem rather than finding
    one.
    """
    accounts = [
        {"Id": "111111111111", "Name": "prod", "Status": "ACTIVE"},
        {"Id": "222222222222", "Name": "dev", "Status": "ACTIVE"},
        {"Id": "333333333333", "Name": "closed", "Status": "SUSPENDED"},
    ]
    monkeypatch.setattr(AwsOnboarding, "_client", _fake_client({"list_accounts": accounts}))

    link = ready()
    found = await AwsOnboarding().discover(link)

    assert [a.account_id for a in found] == ["111111111111", "222222222222"]
    assert [a.display_name for a in found] == ["prod", "dev"]
    assert {a.provider_ref["external_id"] for a in found} == {
        link.provider_ref["external_id"]
    }
    assert found[0].provider_ref["role_arn"] != found[1].provider_ref["role_arn"]


async def test_a_failed_account_listing_discovers_nothing_rather_than_guessing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty result leaves ``last_discovery_at`` unset, so the caller retries.

    Inventing an account list from the management account id would produce a
    connection that scans one account and reports the organization as covered.
    """
    monkeypatch.setattr(AwsOnboarding, "_client", _fake_client({}, fails=True))

    assert await AwsOnboarding().discover(ready()) == []


# ------------------------------------------------------------- teardown
def test_revocation_is_a_stack_deletion_the_customer_runs() -> None:
    """CloudGuard cannot delete a role in someone else's account and would not
    want the permission: ``iam:DeleteRole`` there is far more dangerous than
    the read access it would withdraw."""
    steps = AwsOnboarding().revocation_steps(ready())

    commands = " ".join(step["command"] for step in steps["steps"])
    assert "cloudformation delete-stack" in commands
    assert "your credentials, not CloudGuard's" in steps["why_manual"]


def test_the_scope_reads_as_something_a_customer_recognises() -> None:
    assert AwsOnboarding().scope_path(ready()) == f"organization/{ACCOUNT}"
    assert (
        AwsOnboarding().scope_path(ready(scope_type=ConnectionScope.ACCOUNT))
        == f"account/{ACCOUNT}"
    )


# ---------------------------------------------------------------- helpers
def _fake_client(listings: dict[str, list[dict]], fails: bool = False):
    class FakeClient:
        def __init__(self) -> None:
            self.truncated: set[str] = set()

        async def __aenter__(self) -> "FakeClient":
            if fails:
                raise RuntimeError("denied")
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def call(self, operation: str, **kwargs: Any) -> dict:
            return {}

        async def paginate(self, operation: str, key: str, **kwargs: Any) -> list[dict]:
            return list(listings.get(operation) or [])

    return lambda self, conn, service: FakeClient()
