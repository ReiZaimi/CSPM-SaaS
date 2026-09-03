"""Which stored evidence a scan is allowed to carry forward, against real SQL.

The unit tests cover the judgement -- complete, inside its window, payload still
present. What only a database can hold shut is the scoping: evidence belongs to
one organization and one subscription, and a plan that reached past either would
answer a question about one environment with a reading of another. That is not a
degraded answer, it is a confident wrong one, so each boundary gets a test that
would fail if the ``WHERE`` clause lost a term.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.connectors.azure.evidence import AzureEvidence
from app.core.db import service_session
from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
    Provider,
    ScanStatus,
    TaskOutcome,
)
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.scan import Evidence, EvidenceBlob, Scan
from app.services.evidence_planner import plan_collection
from tests.integration.conftest import create_org_as

pytestmark = pytest.mark.integration

USER = uuid.UUID("11111111-1111-1111-1111-111111111111")
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
# Azure grants no reuse window at all today: role definitions carried one until
# AZ-IAM-003 began reading them, and a key a rule reads may never be answered
# from a stale copy. The mechanism still has to work, and only a database can
# hold its scoping shut -- so a window is granted here, on the inventory, which
# is the one key no rule declares and therefore the one a window could ship for.
REUSABLE = AzureEvidence.RESOURCES
REUSE_WINDOW = timedelta(days=7)
PAYLOAD = {"resources": [{"id": "/x/vm-1", "type": "Microsoft.Compute/virtualMachines"}]}
CONTENT_HASH = "a" * 64
NOW = datetime.now(UTC)


@pytest.fixture(autouse=True)
def _reusable_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give ``REUSABLE`` the window the shipping policy currently gives nothing.

    Patched rather than asserted around, because the alternative is a file of
    tests that pass by doing nothing: with no key carrying a window, every one
    of these would agree that nothing was carried forward and prove none of the
    scoping they exist for.
    """
    from app.connectors.azure import evidence as azure_evidence

    monkeypatch.setitem(azure_evidence._REUSE_WINDOWS, REUSABLE, REUSE_WINDOW)


async def make_tenant(name: str) -> tuple[uuid.UUID, uuid.UUID, list[uuid.UUID]]:
    """An organization with one connection and two subscriptions beneath it."""
    org_id = await create_org_as(USER, name)
    async with service_session() as session:
        connection = CloudConnection(
            organization_id=org_id,
            provider=Provider.AZURE,
            name="tenant",
            scope_type=ConnectionScope.TENANT_ROOT,
            role_version="v1",
            tenant_id=TENANT,
            consent_status=ConsentStatus.GRANTED,
            rbac_verified_at=NOW,
            status=CloudAccountStatus.ACTIVE,
        )
        session.add(connection)
        await session.flush()

        accounts = []
        for n in (1, 2):
            account = CloudAccount(
                organization_id=org_id,
                connection_id=connection.id,
                provider=Provider.AZURE,
                account_name=f"Subscription {n}",
                display_name=f"Subscription {n}",
                tenant_id=TENANT,
                subscription_id=f"00000000-0000-0000-0000-00000000000{n}",
                consent_status=ConsentStatus.GRANTED,
                rbac_verified_at=NOW,
                status=CloudAccountStatus.ACTIVE,
                in_scope=True,
            )
            session.add(account)
            accounts.append(account)
        await session.commit()
        return org_id, connection.id, [a.id for a in accounts]


async def record_reading(
    org_id: uuid.UUID,
    connection_id: uuid.UUID,
    account_id: uuid.UUID | None,
    *,
    age: timedelta = timedelta(days=1),
    outcome: TaskOutcome = TaskOutcome.COMPLETE,
    content_hash: str = CONTENT_HASH,
    store_blob: bool = True,
) -> uuid.UUID:
    """One stored reading, exactly as a completed collection step leaves it."""
    async with service_session() as session:
        scan = Scan(
            organization_id=org_id,
            connection_id=connection_id,
            cloud_account_id=account_id,
            status=ScanStatus.COMPLETED,
        )
        session.add(scan)
        await session.flush()

        if store_blob:
            session.add(
                EvidenceBlob.of(
                    organization_id=org_id,
                    payload=PAYLOAD,
                    content_hash=content_hash,
                    byte_size=len(str(PAYLOAD)),
                    observed_at=datetime.now(UTC),
                )
            )
        session.add(
            Evidence(
                organization_id=org_id,
                scan_id=scan.id,
                cloud_account_id=account_id,
                connection_id=connection_id,
                provider=Provider.AZURE,
                evidence_key=REUSABLE.value,
                category=REUSABLE.category.value,
                outcome=outcome,
                item_count=1,
                collected_at=NOW - age,
                permissions=["Microsoft.Authorization/roleDefinitions/read"],
                content_hash=content_hash,
                byte_size=len(str(PAYLOAD)),
            )
        )
        await session.commit()
        return scan.id


async def plan_for(
    org_id: uuid.UUID,
    connection_id: uuid.UUID,
    account_id: uuid.UUID | None,
    *,
    scan_id: uuid.UUID | None = None,
):
    async with service_session() as session:
        return await plan_collection(
            session,
            organization_id=org_id,
            provider=Provider.AZURE,
            required=frozenset({REUSABLE, AzureEvidence.STORAGE_ACCOUNTS}),
            scan_id=scan_id or uuid.uuid4(),
            cloud_account_id=account_id,
            connection_id=connection_id,
            now=NOW,
        )


async def test_a_stored_reading_is_carried_into_a_later_scan_of_the_same_scope(
    cleanup_orgs,
) -> None:
    org_id, connection_id, accounts = await make_tenant("Planner Carry Org")
    cleanup_orgs.append(org_id)
    await record_reading(org_id, connection_id, accounts[0])

    plan = await plan_for(org_id, connection_id, accounts[0])

    assert plan.carried[REUSABLE].payload == PAYLOAD
    assert not plan.wants(REUSABLE)
    # Everything else in the requirement is still read from the provider.
    assert plan.wants(AzureEvidence.STORAGE_ACCOUNTS)


async def test_one_subscriptions_reading_is_never_carried_into_another(
    cleanup_orgs,
) -> None:
    """Two subscriptions under one grant are two environments.

    They share an organization, a connection and a tenant, so every column but
    one matches -- which is exactly why dropping that one from the query would
    look harmless and answer for the wrong subscription.
    """
    org_id, connection_id, accounts = await make_tenant("Planner Scope Org")
    cleanup_orgs.append(org_id)
    await record_reading(org_id, connection_id, accounts[0])

    plan = await plan_for(org_id, connection_id, accounts[1])

    assert plan.carried == {}
    assert plan.wants(REUSABLE)


async def test_a_subscriptions_reading_is_never_carried_into_the_directory_plan(
    cleanup_orgs,
) -> None:
    """The directory is a reading of the tenant, and its rows carry no account.

    A plan for it matches on ``cloud_account_id IS NULL``, so a subscription's
    reading must not satisfy it however fresh -- the two are readings of
    different things that happen to share a key name.
    """
    org_id, connection_id, accounts = await make_tenant("Planner Directory Org")
    cleanup_orgs.append(org_id)
    await record_reading(org_id, connection_id, accounts[0])

    plan = await plan_for(org_id, connection_id, None)

    assert plan.carried == {}


async def test_another_organizations_reading_is_invisible(cleanup_orgs) -> None:
    """Identical content, different tenant. The saving is never worth this."""
    theirs_org, theirs_connection, theirs_accounts = await make_tenant("Planner Org A")
    ours_org, ours_connection, ours_accounts = await make_tenant("Planner Org B")
    cleanup_orgs.extend([theirs_org, ours_org])
    await record_reading(theirs_org, theirs_connection, theirs_accounts[0])

    plan = await plan_for(ours_org, ours_connection, ours_accounts[0])

    assert plan.carried == {}
    assert plan.wants(REUSABLE)


async def test_the_scans_own_earlier_attempt_is_not_carried_into_its_retry(
    cleanup_orgs,
) -> None:
    """A retried collection step discards what its previous attempt stored.

    Seeing one of those rows here would mean carrying forward the very attempt
    being replaced, so the scan under way is excluded by id rather than by
    trusting the delete to have already happened.
    """
    org_id, connection_id, accounts = await make_tenant("Planner Retry Org")
    cleanup_orgs.append(org_id)
    scan_id = await record_reading(org_id, connection_id, accounts[0])

    plan = await plan_for(org_id, connection_id, accounts[0], scan_id=scan_id)

    assert plan.carried == {}


async def test_a_reading_beyond_its_window_is_read_again(cleanup_orgs) -> None:
    org_id, connection_id, accounts = await make_tenant("Planner Stale Org")
    cleanup_orgs.append(org_id)
    await record_reading(org_id, connection_id, accounts[0], age=timedelta(days=30))

    plan = await plan_for(org_id, connection_id, accounts[0])

    assert plan.carried == {}
    assert plan.wants(REUSABLE)


async def test_a_reading_whose_blob_is_gone_is_read_again(cleanup_orgs) -> None:
    """Retention prunes payloads long before it prunes the record of them."""
    org_id, connection_id, accounts = await make_tenant("Planner Pruned Org")
    cleanup_orgs.append(org_id)
    await record_reading(org_id, connection_id, accounts[0], store_blob=False)

    plan = await plan_for(org_id, connection_id, accounts[0])

    assert plan.carried == {}
    assert plan.wants(REUSABLE)


async def test_a_carried_reading_names_the_scan_that_read_the_provider(
    cleanup_orgs,
) -> None:
    """Provenance survives the reuse, against the real column.

    A carried reading is written again under the reusing scan's own id, so
    without this the trail said that scan called the provider -- and
    ``finding_evidence.source_scan_id``, whose whole purpose is to name the scan
    that collected rather than the scan that concluded, was copied from it.
    """
    org_id, connection_id, accounts = await make_tenant("Planner Source Org")
    cleanup_orgs.append(org_id)
    collecting_scan = await record_reading(org_id, connection_id, accounts[0])

    plan = await plan_for(org_id, connection_id, accounts[0])

    assert plan.carried[REUSABLE].source_scan_id == collecting_scan


async def test_the_source_survives_a_second_reuse(cleanup_orgs) -> None:
    """The chain stays one hop long however many scans reuse a reading.

    A row that was itself carried already names its source. Taking its
    ``scan_id`` instead would credit whichever scan last reused it, and the
    answer would drift one scan further from the reading on every reuse -- which
    is the failure mode the column exists to prevent, arriving slowly.
    """
    org_id, connection_id, accounts = await make_tenant("Planner Chain Org")
    cleanup_orgs.append(org_id)
    original = await record_reading(org_id, connection_id, accounts[0])

    # The reuse, recorded as a collection step leaves it: this scan's own row,
    # holding the original's read time and naming the original as its source.
    async with service_session() as session:
        reuse = Scan(
            organization_id=org_id,
            connection_id=connection_id,
            cloud_account_id=accounts[0],
            status=ScanStatus.COMPLETED,
        )
        session.add(reuse)
        await session.flush()
        session.add(
            Evidence(
                organization_id=org_id,
                scan_id=reuse.id,
                cloud_account_id=accounts[0],
                connection_id=connection_id,
                provider=Provider.AZURE,
                evidence_key=REUSABLE.value,
                category=REUSABLE.category.value,
                outcome=TaskOutcome.COMPLETE,
                item_count=1,
                collected_at=NOW - timedelta(hours=12),
                permissions=["Microsoft.Authorization/roleDefinitions/read"],
                content_hash=CONTENT_HASH,
                byte_size=len(str(PAYLOAD)),
                source_scan_id=original,
            )
        )
        await session.commit()

    plan = await plan_for(org_id, connection_id, accounts[0])

    assert plan.carried[REUSABLE].source_scan_id == original
