"""The full product loop, end to end against a real database.

    connect -> scan -> discover -> evaluate -> findings -> risk
            -> (fix) -> rescan -> verified resolution

The Azure connector is replaced with one that replays a recorded snapshot. That
is test plumbing, not a product component: there is no MockAzureConnector in the
application, and CI should not make live Azure calls on every commit
(TESTING.md section 5 / AZURE_INTEGRATION.md section 1).
"""

import copy
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import text

from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import CloudConnector, NormalizedState, RawSnapshot
from app.core.db import service_session
from app.core.enums import (
    CloudAccountStatus,
    ConsentStatus,
    FindingStatus,
    Level,
    Provider,
    RiskStatus,
    ScanStatus,
)
from app.models.cloud_account import CloudAccount
from app.models.finding import Finding
from app.models.scan import Scan
from app.services import scanner as scanner_module
from app.services.scanner import ScanPipeline
from tests.integration.conftest import create_org_as

pytestmark = pytest.mark.integration

RAW = Path(__file__).parent.parent / "fixtures" / "azure_raw"
USER = uuid.UUID("cccccccc-0000-0000-0000-00000000000c")


def load_raw(name: str = "snapshot_mixed") -> dict:
    return json.loads((RAW / f"{name}.json").read_text())


class ReplayConnector(CloudConnector):
    """Replays a recorded Azure snapshot through the real normalizer."""

    provider = Provider.AZURE

    def __init__(self, payload: dict, **_: object) -> None:
        self.payload = payload
        self._normalizer = AzureNormalizer()

    async def validate_connection(self):  # pragma: no cover -- not used here
        raise NotImplementedError

    async def collect(self, on_progress=None) -> RawSnapshot:
        if on_progress:
            await on_progress(1, 1)
        return RawSnapshot(
            provider=Provider.AZURE,
            tenant_id=self.payload["tenant_id"],
            subscription_id=self.payload["subscription_id"],
            version=self.payload["version"],
            data=copy.deepcopy(self.payload["data"]),
            errors=copy.deepcopy(self.payload["errors"]),
        )

    def normalize(self, snapshot: RawSnapshot) -> NormalizedState:
        return self._normalizer.normalize(snapshot)


@pytest.fixture
def replay(monkeypatch):
    """Point the pipeline at a snapshot of our choosing."""
    holder = {"payload": load_raw()}

    def _factory(_provider, **kwargs):
        return ReplayConnector(holder["payload"], **kwargs)

    monkeypatch.setattr(scanner_module, "get_connector", _factory)
    return holder


@pytest.fixture
async def connected_account(cleanup_orgs):
    org_id = await create_org_as(USER, "Scan Test Org")
    cleanup_orgs.append(org_id)

    async with service_session() as session:
        account = CloudAccount(
            organization_id=org_id,
            provider=Provider.AZURE,
            account_name="Production Subscription",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            subscription_id="00000000-0000-0000-0000-000000000001",
            consent_status=ConsentStatus.GRANTED,
            rbac_verified_at=datetime.now(UTC),
            status=CloudAccountStatus.ACTIVE,
        )
        session.add(account)
        await session.commit()
        return org_id, account.id


@pytest.fixture
async def connected_tenant(cleanup_orgs):
    """A connection with two in-scope subscriptions beneath it."""
    from app.core.enums import ConnectionScope
    from app.models.cloud_connection import CloudConnection

    org_id = await create_org_as(USER, "Tenant Scan Org")
    cleanup_orgs.append(org_id)

    async with service_session() as session:
        connection = CloudConnection(
            organization_id=org_id,
            provider=Provider.AZURE,
            name="tenant",
            scope_type=ConnectionScope.TENANT_ROOT,
            role_version="v1",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            consent_status=ConsentStatus.GRANTED,
            rbac_verified_at=datetime.now(UTC),
            status=CloudAccountStatus.ACTIVE,
        )
        session.add(connection)
        await session.flush()

        for n in (1, 2):
            session.add(
                CloudAccount(
                    organization_id=org_id,
                    connection_id=connection.id,
                    provider=Provider.AZURE,
                    account_name=f"Subscription {n}",
                    display_name=f"Subscription {n}",
                    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    subscription_id=f"00000000-0000-0000-0000-00000000000{n}",
                    consent_status=ConsentStatus.GRANTED,
                    rbac_verified_at=datetime.now(UTC),
                    status=CloudAccountStatus.ACTIVE,
                    in_scope=True,
                )
            )
        await session.commit()
        return org_id, connection.id


async def run_connection_scan(org_id: uuid.UUID, connection_id: uuid.UUID) -> uuid.UUID:
    async with service_session() as session:
        scan = Scan(
            organization_id=org_id,
            connection_id=connection_id,
            status=ScanStatus.QUEUED,
        )
        session.add(scan)
        await session.commit()
        scan_id = scan.id

    await ScanPipeline(scan_id).run()
    return scan_id


async def run_scan(org_id: uuid.UUID, account_id: uuid.UUID) -> uuid.UUID:
    async with service_session() as session:
        scan = Scan(
            organization_id=org_id,
            cloud_account_id=account_id,
            status=ScanStatus.QUEUED,
        )
        session.add(scan)
        await session.commit()
        scan_id = scan.id

    await ScanPipeline(scan_id).run()
    return scan_id


async def run_replay(
    org_id: uuid.UUID, account_id: uuid.UUID, source_scan_id: uuid.UUID
) -> uuid.UUID:
    async with service_session() as session:
        scan = Scan(
            organization_id=org_id,
            cloud_account_id=account_id,
            status=ScanStatus.QUEUED,
            replay_of_scan_id=source_scan_id,
        )
        session.add(scan)
        await session.commit()
        scan_id = scan.id

    await ScanPipeline(scan_id).replay()
    return scan_id


async def fetch(sql: str, params: dict) -> list:
    async with service_session() as session:
        return list((await session.execute(text(sql), params)).all())


class TestFirstScan:
    async def test_scan_completes_and_records_a_snapshot(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
            snapshot = (
                await session.execute(
                    text("SELECT id FROM cloud_snapshots WHERE scan_id = :s"),
                    {"s": scan_id},
                )
            ).scalar_one_or_none()

        assert scan.status == ScanStatus.COMPLETED
        assert scan.resource_count > 0
        assert scan.rule_count == 10
        # Every scan produces exactly one snapshot -- no exceptions.
        assert snapshot is not None

    async def test_assets_are_discovered(self, replay, connected_account) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT resource_type, name FROM cloud_resources WHERE organization_id = :o",
            {"o": org_id},
        )
        types = {r[0] for r in rows}
        assert "network_security_group" in types
        assert "virtual_machine" in types
        assert "storage_account" in types
        assert "sql_server" in types
        assert "user" in types

    async def test_findings_are_created_with_evidence_and_remediation(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            findings = list(
                (
                    await session.execute(
                        text("SELECT * FROM findings WHERE organization_id = :o"),
                        {"o": org_id},
                    )
                ).mappings()
            )

        assert findings, "the vulnerable fixture must produce findings"
        by_rule = {f["rule_id"]: f for f in findings}
        assert "AZ-NET-001" in by_rule    # RDP open to the internet
        assert "AZ-DB-001" in by_rule     # SQL firewall allows everything

        rdp = by_rule["AZ-NET-001"]
        # Every finding needs evidence (SECURITY.md section 1, rule 8).
        assert rdp["evidence"]["port"] == 3389
        # Remediation is snapshot-copied at creation, not looked up later.
        assert "az network nsg rule update" in rdp["remediation"]
        assert rdp["rule_version"] == "1.0"
        assert rdp["status"] == FindingStatus.OPEN

    async def test_finding_titles_name_the_asset_in_plain_language(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT title FROM findings WHERE organization_id = :o AND rule_id = 'AZ-NET-001'",
            {"o": org_id},
        )
        title = rows[0][0]
        assert "nsg-jumpbox" in title
        assert "RDP" in title

    async def test_every_finding_gets_a_scored_risk(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            risks = list(
                (
                    await session.execute(
                        text(
                            "SELECT r.risk_score, r.risk_level, r.score_breakdown, f.rule_id "
                            "FROM risks r "
                            "JOIN risk_findings rf ON rf.risk_id = r.id "
                            "JOIN findings f ON f.id = rf.finding_id "
                            "WHERE r.organization_id = :o"
                        ),
                        {"o": org_id},
                    )
                ).mappings()
            )

        assert risks
        for risk in risks:
            assert 0 <= float(risk["risk_score"]) <= 100
            assert risk["score_breakdown"]["components"]

        # The RDP finding sits on a production, internet-exposed asset.
        rdp = next(r for r in risks if r["rule_id"] == "AZ-NET-001")
        assert float(rdp["risk_score"]) >= 75
        assert rdp["risk_level"] == Level.CRITICAL

    async def test_coverage_is_recorded_for_every_rule(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT rule_id, passed_count, failed_count, unknown_count, "
            "not_applicable_count FROM scan_rule_results WHERE scan_id = :s",
            {"s": scan_id},
        )
        assert len(rows) == 10, "one aggregate row per rule in the registry"


class TestUnknownHandling:
    async def test_collection_failure_produces_gaps_not_findings(
        self, replay, connected_account
    ) -> None:
        """A storage API timeout must never read as "no storage problems"."""
        org_id, account_id = connected_account
        replay["payload"]["errors"] = {"storage": "Azure Storage API timed out"}

        scan_id = await run_scan(org_id, account_id)

        gaps = await fetch(
            "SELECT rule_id, reason FROM scan_evaluation_gaps WHERE scan_id = :s",
            {"s": scan_id},
        )
        storage_gaps = [g for g in gaps if g[0].startswith("AZ-STO")]
        assert storage_gaps, "storage rules must be recorded as UNKNOWN"
        assert "timed out" in storage_gaps[0][1]

        storage_findings = await fetch(
            "SELECT rule_id FROM findings WHERE organization_id = :o "
            "AND rule_id LIKE 'AZ-STO%'",
            {"o": org_id},
        )
        assert storage_findings == [], "UNKNOWN must never become a Finding"

    async def test_partial_scan_status_when_a_category_failed(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        replay["payload"]["errors"] = {"storage": "Azure Storage API timed out"}
        scan_id = await run_scan(org_id, account_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
        assert scan.status == ScanStatus.PARTIAL
        assert "storage" in scan.collection_errors


class TestRemediationVerification:
    """Requirement 13: a rescan verifies the fix. No human marks anything."""

    async def test_rescan_auto_resolves_a_fixed_finding(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account

        # --- scan 1: RDP is open --------------------------------------------
        await run_scan(org_id, account_id)
        rows = await fetch(
            "SELECT id, status FROM findings WHERE organization_id = :o "
            "AND rule_id = 'AZ-NET-001'",
            {"o": org_id},
        )
        assert rows[0][1] == FindingStatus.OPEN
        finding_id = rows[0][0]

        # --- the customer fixes it ------------------------------------------
        fixed = load_raw()
        for nsg in fixed["data"]["network_security_groups"]:
            for rule in nsg["properties"]["securityRules"]:
                if rule["name"] == "AllowRDP":
                    rule["properties"]["sourceAddressPrefix"] = "10.10.0.0/16"
        replay["payload"] = fixed

        # --- scan 2: verification -------------------------------------------
        scan_2 = await run_scan(org_id, account_id)

        async with service_session() as session:
            finding = await session.get(Finding, finding_id)

        assert finding.status == FindingStatus.RESOLVED
        assert finding.resolved_at is not None
        # Stamped with the scan that proved it -- this IS the verification.
        assert finding.resolved_by_scan_id == scan_2

    async def test_resolving_a_finding_resolves_its_risk(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        fixed = load_raw()
        for nsg in fixed["data"]["network_security_groups"]:
            for rule in nsg["properties"]["securityRules"]:
                if rule["name"] == "AllowRDP":
                    rule["properties"]["sourceAddressPrefix"] = "10.10.0.0/16"
        replay["payload"] = fixed
        await run_scan(org_id, account_id)

        async with service_session() as session:
            status = (
                await session.execute(
                    text(
                        "SELECT r.status FROM risks r "
                        "JOIN risk_findings rf ON rf.risk_id = r.id "
                        "JOIN findings f ON f.id = rf.finding_id "
                        "WHERE f.organization_id = :o AND f.rule_id = 'AZ-NET-001'"
                    ),
                    {"o": org_id},
                )
            ).scalar_one()
        assert status == RiskStatus.RESOLVED

    async def test_unknown_on_rescan_does_not_resolve_a_finding(
        self, replay, connected_account
    ) -> None:
        """Failing to look is not the same as looking and finding nothing."""
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        replay["payload"] = load_raw()
        replay["payload"]["errors"] = {"network": "Azure Network API timed out"}
        await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT status FROM findings WHERE organization_id = :o "
            "AND rule_id = 'AZ-NET-001'",
            {"o": org_id},
        )
        assert rows[0][0] == FindingStatus.OPEN

    async def test_a_regression_reopens_a_resolved_finding(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        fixed = load_raw()
        for nsg in fixed["data"]["network_security_groups"]:
            for rule in nsg["properties"]["securityRules"]:
                if rule["name"] == "AllowRDP":
                    rule["properties"]["sourceAddressPrefix"] = "10.10.0.0/16"
        replay["payload"] = fixed
        await run_scan(org_id, account_id)

        # Someone re-opens the port.
        replay["payload"] = load_raw()
        await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT status, resolved_at FROM findings WHERE organization_id = :o "
            "AND rule_id = 'AZ-NET-001'",
            {"o": org_id},
        )
        assert rows[0][0] == FindingStatus.OPEN
        assert rows[0][1] is None

    async def test_findings_are_not_duplicated_across_scans(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT rule_id, count(*) FROM findings WHERE organization_id = :o "
            "GROUP BY rule_id HAVING count(*) > 1",
            {"o": org_id},
        )
        assert rows == [], "a re-detection must update, not duplicate"


class TestSecurityScoreMoves:
    async def test_score_improves_after_a_verified_fix(
        self, replay, connected_account
    ) -> None:
        """The MVP success condition: the score moves when a fix is verified."""
        from app.services.dashboard import build_dashboard

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            before = await build_dashboard(session, org_id)

        fixed = load_raw()
        for nsg in fixed["data"]["network_security_groups"]:
            for rule in nsg["properties"]["securityRules"]:
                if rule["name"] == "AllowRDP":
                    rule["properties"]["sourceAddressPrefix"] = "10.10.0.0/16"
        for server in fixed["data"]["sql_servers"]:
            server["properties"]["publicNetworkAccess"] = "Disabled"
            server["_firewall_rules"] = []
        replay["payload"] = fixed
        await run_scan(org_id, account_id)

        async with service_session() as session:
            after = await build_dashboard(session, org_id)

        assert after["security_score"] > before["security_score"]
        assert after["open_finding_count"] < before["open_finding_count"]
        assert after["verified_resolved_last_30_days"] >= 2


class TestSnapshotReplay:
    """Re-evaluating a stored capture, without going back to Azure.

    Every scan above wrote a snapshot before interpreting anything, on the
    promise that it could be re-evaluated later against improved rules. These
    tests are that promise being kept -- and the guard rail that stops it
    becoming a way to fabricate evidence.
    """

    async def test_a_replay_reproduces_the_scan_it_replayed(
        self, replay, connected_account
    ) -> None:
        """Same snapshot, same rules, same answer. If this ever diverged, a
        stored snapshot would stop being worth keeping."""
        org_id, account_id = connected_account
        original_id = await run_scan(org_id, account_id)

        replayed_id = await run_replay(org_id, account_id, original_id)

        async with service_session() as session:
            original = await session.get(Scan, original_id)
            replayed = await session.get(Scan, replayed_id)

        assert replayed.status == original.status
        assert replayed.resource_count == original.resource_count
        assert replayed.rule_count == original.rule_count
        assert replayed.finding_count == original.finding_count
        assert replayed.replay_of_scan_id == original_id

    async def test_a_replay_makes_no_azure_call(
        self, replay, connected_account, monkeypatch
    ) -> None:
        """The point of the feature. A connector that raises on ``collect``
        proves the replay path never reaches for the network."""
        org_id, account_id = connected_account
        original_id = await run_scan(org_id, account_id)

        async def explode() -> RawSnapshot:
            raise AssertionError("a replay must not collect")

        monkeypatch.setattr(ReplayConnector, "collect", lambda self: explode())

        replayed_id = await run_replay(org_id, account_id, original_id)
        async with service_session() as session:
            replayed = await session.get(Scan, replayed_id)
        assert replayed.status == ScanStatus.COMPLETED

    async def test_a_replay_writes_no_second_snapshot(
        self, replay, connected_account
    ) -> None:
        """One snapshot per collection, not one per evaluation."""
        org_id, account_id = connected_account
        original_id = await run_scan(org_id, account_id)
        await run_replay(org_id, account_id, original_id)

        rows = await fetch(
            "SELECT count(*) FROM cloud_snapshots WHERE organization_id = :o",
            {"o": org_id},
        )
        assert rows[0][0] == 1

    async def test_a_replay_of_the_newest_snapshot_verifies_fixes(
        self, replay, connected_account
    ) -> None:
        """A replay of current state is a scan that skipped collection, so the
        remediation loop still closes -- including the case that matters, where
        the rule proving the fix was written after the fix was made."""
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        fixed = load_raw()
        for nsg in fixed["data"]["network_security_groups"]:
            for rule in nsg["properties"]["securityRules"]:
                if rule["name"] == "AllowRDP":
                    rule["properties"]["sourceAddressPrefix"] = "10.10.0.0/16"
        replay["payload"] = fixed
        fixed_scan_id = await run_scan(org_id, account_id)

        # Replaying that same, newest snapshot must reach the same verdict.
        replayed_id = await run_replay(org_id, account_id, fixed_scan_id)

        async with service_session() as session:
            replayed = await session.get(Scan, replayed_id)
            rows = list(
                (
                    await session.execute(
                        text(
                            "SELECT status FROM findings "
                            "WHERE organization_id = :o AND rule_id = 'AZ-NET-001'"
                        ),
                        {"o": org_id},
                    )
                ).scalars()
            )

        assert replayed.evaluation_only is False
        assert rows and all(s == FindingStatus.RESOLVED for s in rows)

    async def test_a_replay_of_a_superseded_snapshot_resolves_nothing(
        self, replay, connected_account
    ) -> None:
        """The interlock, end to end.

        The first snapshot shows RDP open. The second shows it closed, which
        resolves the finding. Replaying the *first* one now produces FAIL again
        -- and must not reopen anything, because that capture is a statement
        about the past. A month-old snapshot cannot testify to the present in
        either direction.
        """
        org_id, account_id = connected_account
        stale_scan_id = await run_scan(org_id, account_id)

        fixed = load_raw()
        for nsg in fixed["data"]["network_security_groups"]:
            for rule in nsg["properties"]["securityRules"]:
                if rule["name"] == "AllowRDP":
                    rule["properties"]["sourceAddressPrefix"] = "10.10.0.0/16"
        replay["payload"] = fixed
        await run_scan(org_id, account_id)

        before = await fetch(
            "SELECT id, status, resolved_by_scan_id FROM findings "
            "WHERE organization_id = :o ORDER BY id",
            {"o": org_id},
        )
        replayed_id = await run_replay(org_id, account_id, stale_scan_id)
        after = await fetch(
            "SELECT id, status, resolved_by_scan_id FROM findings "
            "WHERE organization_id = :o ORDER BY id",
            {"o": org_id},
        )

        assert after == before, "a superseded snapshot must not change any finding"

        async with service_session() as session:
            replayed = await session.get(Scan, replayed_id)
        # It still reports what the rules would have found, and still records
        # coverage -- what could and could not be determined about that capture
        # is true whatever its age.
        assert replayed.evaluation_only is True
        assert replayed.status == ScanStatus.COMPLETED
        assert replayed.finding_count > 0

        gaps = await fetch(
            "SELECT count(*) FROM scan_rule_results WHERE scan_id = :s",
            {"s": replayed_id},
        )
        assert gaps[0][0] > 0

    async def test_a_superseded_replay_leaves_the_asset_inventory_alone(
        self, replay, connected_account
    ) -> None:
        """The columns the risk scorer reads must not be rewritten from a
        capture that has been superseded.

        ``last_seen_at`` was guarded from the start; every other column was
        assigned outright, so a replay of an old snapshot wrote historical
        exposure and metadata over live rows and re-created resources deleted
        since. This asserts the whole row, not one field.
        """
        org_id, account_id = connected_account
        stale_scan_id = await run_scan(org_id, account_id)

        # The environment moves on: a storage account is locked down, and the
        # snapshot it is locked down in becomes the newest.
        fixed = load_raw()
        for account in fixed["data"]["storage_accounts"]:
            account["properties"]["allowBlobPublicAccess"] = False
        replay["payload"] = fixed
        await run_scan(org_id, account_id)

        before = await fetch(
            "SELECT id, resource_type, name, region, criticality, data_sensitivity, "
            "public_exposure, metadata, first_seen_at, last_seen_at "
            "FROM cloud_resources WHERE organization_id = :o ORDER BY id",
            {"o": org_id},
        )
        await run_replay(org_id, account_id, stale_scan_id)
        after = await fetch(
            "SELECT id, resource_type, name, region, criticality, data_sensitivity, "
            "public_exposure, metadata, first_seen_at, last_seen_at "
            "FROM cloud_resources WHERE organization_id = :o ORDER BY id",
            {"o": org_id},
        )

        assert after == before, "a superseded capture must not rewrite any asset"

    async def test_replaying_a_replay_resolves_to_the_capture_underneath(
        self, replay, connected_account
    ) -> None:
        """Only a scan that collected owns a snapshot, so pointing a replay at
        another replay would queue a run guaranteed to fail."""
        org_id, account_id = connected_account
        original_id = await run_scan(org_id, account_id)
        first_replay_id = await run_replay(org_id, account_id, original_id)

        async with service_session() as session:
            second = Scan(
                organization_id=org_id,
                cloud_account_id=account_id,
                status=ScanStatus.QUEUED,
                replay_of_scan_id=first_replay_id,
            )
            session.add(second)
            await session.commit()
            second_id = second.id

        # Pointed straight at a replay, the pipeline has nothing to read and
        # says so rather than raising -- the route is what resolves the chain.
        await ScanPipeline(second_id).replay()
        async with service_session() as session:
            failed = await session.get(Scan, second_id)
        assert failed.status == ScanStatus.FAILED
        assert "no stored snapshot" in failed.error_message

    async def test_a_replay_does_not_backdate_last_seen_on_assets(
        self, replay, connected_account
    ) -> None:
        """``last_seen_at`` means when the resource was observed. A replay of an
        old capture must not report a resource as seen today, nor drag a
        currently-seen one backwards."""
        org_id, account_id = connected_account
        stale_scan_id = await run_scan(org_id, account_id)
        before = await fetch(
            "SELECT id, last_seen_at FROM cloud_resources "
            "WHERE organization_id = :o ORDER BY id",
            {"o": org_id},
        )

        await run_replay(org_id, account_id, stale_scan_id)
        after = await fetch(
            "SELECT id, last_seen_at FROM cloud_resources "
            "WHERE organization_id = :o ORDER BY id",
            {"o": org_id},
        )
        assert after == before

    async def test_replaying_a_scan_with_no_snapshot_fails_with_a_reason(
        self, replay, connected_account
    ) -> None:
        """A scan that failed before collection finished has nothing to replay,
        and must say so rather than raising."""
        org_id, account_id = connected_account
        async with service_session() as session:
            empty = Scan(
                organization_id=org_id,
                cloud_account_id=account_id,
                status=ScanStatus.FAILED,
            )
            session.add(empty)
            await session.commit()
            empty_id = empty.id

        replayed_id = await run_replay(org_id, account_id, empty_id)
        async with service_session() as session:
            replayed = await session.get(Scan, replayed_id)

        assert replayed.status == ScanStatus.FAILED
        assert "no stored snapshot" in replayed.error_message


class TestTenantWideScan:
    """One scan across every in-scope subscription under a connection.

    Fifty subscriptions used to mean fifty scans, fifty snapshots and fifty
    security scores, with no rule able to see across them.
    """

    async def test_one_scan_covers_every_in_scope_subscription(
        self, replay, connected_tenant
    ) -> None:
        org_id, connection_id = connected_tenant
        scan_id = await run_connection_scan(org_id, connection_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)

        assert scan.status == ScanStatus.COMPLETED
        assert scan.connection_id == connection_id
        assert scan.cloud_account_id is None, "scoped to the connection, not one sub"

    async def test_each_subscription_keeps_its_own_verbatim_snapshot(
        self, replay, connected_tenant
    ) -> None:
        """Merging them before storage would destroy the only property a
        snapshot has, which is that it is what Azure actually said."""
        org_id, connection_id = connected_tenant
        scan_id = await run_connection_scan(org_id, connection_id)

        rows = await fetch(
            "SELECT cloud_account_id FROM cloud_snapshots WHERE scan_id = :s",
            {"s": scan_id},
        )
        assert len(rows) == 2
        assert len({r[0] for r in rows}) == 2, "one per subscription"

    async def test_resources_from_both_subscriptions_land_in_one_scan(
        self, replay, connected_tenant
    ) -> None:
        org_id, connection_id = connected_tenant
        scan_id = await run_connection_scan(org_id, connection_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)

        assert scan.resource_count > 0
        # Both subscriptions replay the same fixture, so every resource is
        # discovered twice -- once per subscription, under its own account.
        rows = await fetch(
            "SELECT DISTINCT cloud_account_id FROM cloud_resources "
            "WHERE organization_id = :o",
            {"o": org_id},
        )
        assert len(rows) == 2, "assets attributed to the subscription they came from"

    async def test_a_scan_with_nothing_in_scope_says_so(
        self, replay, connected_tenant
    ) -> None:
        """Excluding every subscription leaves a connection that cannot be
        scanned, and a scan that reported COMPLETED over zero subscriptions
        would be a clean bill of health for an environment nobody read."""
        org_id, connection_id = connected_tenant
        async with service_session() as session:
            await session.execute(
                text(
                    "UPDATE cloud_accounts SET in_scope = false "
                    "WHERE connection_id = :c"
                ),
                {"c": connection_id},
            )
            await session.commit()

        scan_id = await run_connection_scan(org_id, connection_id)
        async with service_session() as session:
            scan = await session.get(Scan, scan_id)

        assert scan.status == ScanStatus.FAILED
        assert "nothing in scope" in scan.error_message

    async def test_a_tenant_wide_scan_replays_every_subscription(
        self, replay, connected_tenant
    ) -> None:
        org_id, connection_id = connected_tenant
        original_id = await run_connection_scan(org_id, connection_id)

        async with service_session() as session:
            scan = Scan(
                organization_id=org_id,
                connection_id=connection_id,
                status=ScanStatus.QUEUED,
                replay_of_scan_id=original_id,
            )
            session.add(scan)
            await session.commit()
            replay_id = scan.id

        await ScanPipeline(replay_id).replay()

        async with service_session() as session:
            original = await session.get(Scan, original_id)
            replayed = await session.get(Scan, replay_id)

        assert replayed.status == original.status
        assert replayed.resource_count == original.resource_count
        assert replayed.evaluation_only is False, "these are still the newest"

    async def test_collection_failures_name_the_subscription_they_came_from(
        self, replay, connected_tenant
    ) -> None:
        """"storage: timeout" twice over says nothing about which subscription
        to go and look at."""
        broken = load_raw()
        broken["errors"] = {"storage": "read tcp: i/o timeout"}
        replay["payload"] = broken

        org_id, connection_id = connected_tenant
        scan_id = await run_connection_scan(org_id, connection_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)

        assert scan.status == ScanStatus.PARTIAL
        assert len(scan.collection_errors) == 2, "one per subscription"
        assert all("Subscription" in key for key in scan.collection_errors)
