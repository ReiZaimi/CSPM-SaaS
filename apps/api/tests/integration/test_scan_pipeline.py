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
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import CloudConnector, NormalizedState, RawSnapshot
from app.core.db import service_session
from app.core.enums import (
    CloudAccountStatus,
    CollectionScope,
    ConsentStatus,
    FindingStatus,
    Level,
    Provider,
    RiskStatus,
    ScanStatus,
    ScanStepKind,
    ScanStepStatus,
    TaskOutcome,
)
from app.models.cloud_account import CloudAccount
from app.models.finding import Finding
from app.models.scan import Scan, ScanStep
from app.services import orchestrator
from app.services import scanner as scanner_module
from app.services import scans as scans_service
from app.services.scanner import ScanPipeline
from app.services.scans import DIRECTORY_LABEL
from tests.integration.conftest import create_org_as

pytestmark = pytest.mark.integration

RAW = Path(__file__).parent.parent / "fixtures" / "azure_raw"
USER = uuid.UUID("cccccccc-0000-0000-0000-00000000000c")


def load_raw(name: str = "snapshot_mixed") -> dict:
    return json.loads((RAW / f"{name}.json").read_text())


# The recorded fixture is one file covering a whole scan, but a scan reads two
# scopes and the pipeline asks for them separately. These are the keys that
# belong to the tenant rather than to any subscription in it.
DIRECTORY_KEYS = frozenset(
    {"users", "directory_roles", "user_role_map", "authentication_methods"}
)
DIRECTORY_CATEGORY = "identity"

# Which payload keys each reading owns. The real plan does not need this -- a
# task returns its own output and the executor keeps it -- but the recording is
# one merged blob, so the double has to say how to cut it up again. Only the
# task that produces two is listed; every other reading owns the key it is
# named after.
OWNED_PAYLOAD_KEYS = {"user_role_map": ("user_role_map", "authentication_methods")}


class ReplayConnector(CloudConnector):
    """Replays a recorded Azure snapshot through the real normalizer.

    Splits the recording the same way the real connector splits its plans: the
    directory half answers ``collect_directory`` once per scan, the rest answers
    ``collect`` once per subscription. Serving the whole recording to both would
    hide the bug these tests exist to hold shut -- the users would come back per
    subscription again, exactly as they did before the split.
    """

    provider = Provider.AZURE

    def __init__(self, payload: dict, **_: object) -> None:
        self.payload = payload
        self._normalizer = AzureNormalizer()

    async def validate_connection(self):  # pragma: no cover -- not used here
        raise NotImplementedError

    async def collect(self, on_progress=None) -> RawSnapshot:
        if on_progress:
            await on_progress(1, 1)
        return self._slice(directory=False)

    async def collect_directory(self, on_progress=None) -> RawSnapshot:
        if on_progress:
            await on_progress(1, 1)
        return self._slice(directory=True)

    def _slice(self, *, directory: bool) -> RawSnapshot:
        snapshot = RawSnapshot.from_json(copy.deepcopy(self.payload))
        snapshot.data = {
            key: value
            for key, value in snapshot.data.items()
            if (key in DIRECTORY_KEYS) is directory
        }
        snapshot.coverage = {
            key: entry
            for key, entry in snapshot.coverage.items()
            if (entry.get("category") == DIRECTORY_CATEGORY) is directory
        }
        # ``errors`` is injected directly by tests rather than derived, so it is
        # filtered on the same axis: an identity error belongs to the directory
        # capture and a storage error to the subscription's.
        snapshot.errors = {
            category: reason
            for category, reason in snapshot.errors.items()
            if (category == DIRECTORY_CATEGORY) is directory
        }
        if directory:
            snapshot.subscription_id = None
            snapshot.scope = CollectionScope.DIRECTORY

        self._align_coverage(snapshot)
        # Derived last, from the coverage this slice actually kept -- the same
        # order a real run uses. Tests inject a category error and expect the
        # rules under it to degrade, which only happens if the per-key gaps are
        # rebuilt after the injection rather than inherited from the recording.
        snapshot.gaps = {
            key: entry.get("detail") or entry["outcome"].lower()
            for key, entry in snapshot.coverage.items()
            if entry["outcome"] != TaskOutcome.COMPLETE.value
        }
        # And the per-reading payloads, which a real run gets for free because
        # each task returns its own output. A task that failed produced nothing,
        # so it contributes none -- which is what leaves its evidence row
        # pointing at no payload rather than at a hash of an empty object.
        snapshot.payloads = {}
        for key, entry in snapshot.coverage.items():
            if entry["outcome"] in (
                TaskOutcome.FAILED.value,
                TaskOutcome.SKIPPED.value,
            ):
                continue
            owned = {
                name: snapshot.data[name]
                for name in OWNED_PAYLOAD_KEYS.get(key, (key,))
                if name in snapshot.data
            }
            if owned:
                snapshot.payloads[key] = owned
        return snapshot

    @staticmethod
    def _align_coverage(snapshot: RawSnapshot) -> None:
        """Keep the recorded coverage consistent with injected errors.

        A real run derives ``errors`` from ``coverage``; tests inject the
        errors directly, so the derivation has to be run backwards here. Left
        alone, a test that fails a category would still record every task of it
        as COMPLETE, and the collection status would contradict the scan.
        """
        for entry in snapshot.coverage.values():
            reason = snapshot.errors.get(entry["category"])
            if reason:
                entry["outcome"] = TaskOutcome.FAILED.value
                entry["detail"] = reason

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
    """One subscription, beneath the connection that grants access to it.

    The connection is not decoration. A subscription is discovered under a
    connection and never exists without one in production, and the connection is
    what the tenant directory is read through -- so an account without one is a
    shape the pipeline is right to refuse the directory for, and the wrong thing
    to write the rest of these tests against.
    """
    from app.core.enums import ConnectionScope
    from app.models.cloud_connection import CloudConnection

    org_id = await create_org_as(USER, "Scan Test Org")
    cleanup_orgs.append(org_id)

    async with service_session() as session:
        connection = CloudConnection(
            organization_id=org_id,
            provider=Provider.AZURE,
            name="production",
            scope_type=ConnectionScope.TENANT_ROOT,
            role_version="v1",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            consent_status=ConsentStatus.GRANTED,
            rbac_verified_at=datetime.now(UTC),
            status=CloudAccountStatus.ACTIVE,
        )
        session.add(connection)
        await session.flush()

        account = CloudAccount(
            organization_id=org_id,
            connection_id=connection.id,
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


async def drive(scan_id: uuid.UUID, *, max_rounds: int = 20) -> uuid.UUID:
    """Run a scan to completion the way the workers would.

    The same loop ``advance_scan`` and ``run_scan_step`` perform between them:
    ask what may run, claim it, run it, ask again. Written out here rather than
    calling the Celery tasks so the test needs no broker -- but every decision
    it makes is the orchestrator's and the pipeline's, not this helper's.

    ``max_rounds`` bounds it so a dependency bug shows up as a failing test
    rather than as a suite that never finishes.
    """
    async with service_session() as session:
        scan = await session.get(Scan, scan_id)
        await orchestrator.create_initial_steps(session, scan)
        await session.commit()

    for _ in range(max_rounds):
        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
            steps = await orchestrator.sync_scan_state(session, scan)
            ready = orchestrator.runnable(steps)
            claimed = await orchestrator.claim(session, [s.id for s in ready])
        if not claimed:
            break
        for step_id in claimed:
            await ScanPipeline(scan_id).run_step(step_id)
    else:  # pragma: no cover - a dependency that never settles
        raise AssertionError(f"scan {scan_id} did not settle in {max_rounds} rounds")

    async with service_session() as session:
        scan = await session.get(Scan, scan_id)
        await orchestrator.sync_scan_state(session, scan)
    return scan_id


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

    return await drive(scan_id)


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

    return await drive(scan_id)


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
    async def test_scan_completes_and_records_a_capture_per_scope(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)

        assert scan.status == ScanStatus.COMPLETED
        assert scan.resource_count > 0
        assert scan.rule_count == 10

        # A capture per scope, not one per scan. This scan read one
        # subscription and the tenant directory above it, and both are stored
        # verbatim: merging them would lose the property a snapshot exists for,
        # which is that it is what the provider actually said about one thing.
        captures = await fetch(
            "SELECT cloud_account_id FROM cloud_snapshots WHERE scan_id = :s",
            {"s": scan_id},
        )
        assert len([c for c in captures if c[0] == account_id]) == 1
        assert len([c for c in captures if c[0] is None]) == 1, (
            "the tenant directory is captured once per scan"
        )

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
        """Snapshots come from collection, not from evaluation.

        Counted before and after rather than against a fixed number: what the
        test is about is that a replay adds none, and how many the collecting
        scan wrote is a fact about its scope -- one subscription plus the tenant
        directory today, more when it covers more.
        """
        org_id, account_id = connected_account
        original_id = await run_scan(org_id, account_id)
        collected = await fetch(
            "SELECT count(*) FROM cloud_snapshots WHERE organization_id = :o",
            {"o": org_id},
        )
        assert collected[0][0] > 0, "the scan should have captured something"

        await run_replay(org_id, account_id, original_id)

        after = await fetch(
            "SELECT count(*) FROM cloud_snapshots WHERE organization_id = :o",
            {"o": org_id},
        )
        assert after == collected, "a replay collected nothing and must store nothing"

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
        """``last_seen_at`` means when the resource was observed, and a replay
        must never drag it backwards -- that is what would make a live resource
        read as stale.

        Not asserted as exact equality, because the two runs read the clock in
        different places: a scan stamps ``observed_at`` from Python before the
        snapshot row exists, while a replay uses the snapshot's own
        server-generated ``created_at``, a few milliseconds later. The
        monotonicity is the invariant; the millisecond is not. Strict equality
        is asserted where it is actually true --
        ``test_a_superseded_replay_leaves_the_asset_inventory_alone``, where
        nothing is written at all.
        """
        org_id, account_id = connected_account
        stale_scan_id = await run_scan(org_id, account_id)
        before = dict(
            await fetch(
                "SELECT id, last_seen_at FROM cloud_resources "
                "WHERE organization_id = :o",
                {"o": org_id},
            )
        )

        await run_replay(org_id, account_id, stale_scan_id)
        after = dict(
            await fetch(
                "SELECT id, last_seen_at FROM cloud_resources "
                "WHERE organization_id = :o",
                {"o": org_id},
            )
        )

        assert set(after) == set(before), "a replay must not add or drop assets"
        for resource_id, seen in after.items():
            assert seen >= before[resource_id], "last_seen_at moved backwards"

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
        accounts = [r[0] for r in rows if r[0] is not None]
        assert len(accounts) == 2
        assert len(set(accounts)) == 2, "one per subscription"

    async def test_the_directory_is_captured_once_for_the_whole_scan(
        self, replay, connected_tenant
    ) -> None:
        """Not once per subscription. The tenant is the same tenant from each of
        them, and a second capture would be a second copy of one answer."""
        org_id, connection_id = connected_tenant
        scan_id = await run_connection_scan(org_id, connection_id)

        rows = await fetch(
            "SELECT connection_id FROM cloud_snapshots "
            "WHERE scan_id = :s AND cloud_account_id IS NULL",
            {"s": scan_id},
        )
        assert len(rows) == 1, "one directory capture per scan"
        assert rows[0][0] == connection_id

    async def test_resources_from_both_subscriptions_land_in_one_scan(
        self, replay, connected_tenant
    ) -> None:
        org_id, connection_id = connected_tenant
        scan_id = await run_connection_scan(org_id, connection_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)

        assert scan.resource_count > 0
        # Both subscriptions replay the same fixture, so every subscription
        # resource is discovered twice -- once per subscription, under its own
        # account.
        rows = await fetch(
            "SELECT DISTINCT cloud_account_id FROM cloud_resources "
            "WHERE organization_id = :o AND cloud_account_id IS NOT NULL",
            {"o": org_id},
        )
        assert len(rows) == 2, "assets attributed to the subscription they came from"

    async def test_a_directory_user_is_one_asset_not_one_per_subscription(
        self, replay, connected_tenant
    ) -> None:
        """The regression this whole split exists for.

        Directory tasks used to run inside the per-subscription plan, so each
        subscription contributed its own copy of every user. ``cloud_resources``
        is unique on (cloud_account_id, provider_resource_id), so the copies
        were separate asset rows -- and a finding is identified by
        (organization, rule, resource), which turned one administrator without
        MFA into one CRITICAL finding per subscription.
        """
        org_id, connection_id = connected_tenant
        await run_connection_scan(org_id, connection_id)

        rows = await fetch(
            "SELECT provider_resource_id, count(*) FROM cloud_resources "
            "WHERE organization_id = :o AND resource_type = 'user' "
            "GROUP BY provider_resource_id",
            {"o": org_id},
        )
        assert rows, "the fixture is supposed to contain directory users"
        assert all(count == 1 for _id, count in rows), (
            "a directory user is one asset in the tenant, not one per subscription"
        )
        assert all(r[0] is None for r in await fetch(
            "SELECT cloud_account_id FROM cloud_resources "
            "WHERE organization_id = :o AND resource_type = 'user'",
            {"o": org_id},
        )), "a user belongs to the tenant, so it names no subscription"

    async def test_one_administrator_raises_one_finding(
        self, replay, connected_tenant
    ) -> None:
        """The same regression, at the layer the customer would have seen it."""
        org_id, connection_id = connected_tenant
        await run_connection_scan(org_id, connection_id)

        rows = await fetch(
            "SELECT rule_id, resource_id, count(*) FROM findings "
            "WHERE organization_id = :o AND rule_id = 'AZ-ID-001' "
            "GROUP BY rule_id, resource_id",
            {"o": org_id},
        )
        # However many administrators the fixture holds, each is one row. Two
        # subscriptions must not double them.
        assert all(count == 1 for *_keys, count in rows)

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


class TestCollectionStatus:
    """The record of what a scan managed to read, as facts rather than prose."""

    async def test_every_task_records_its_outcome(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT evidence_key, outcome FROM evidence WHERE scan_id = :s",
            {"s": scan_id},
        )
        assert rows, "collection status was recorded"
        assert {r[1] for r in rows} == {"COMPLETE"}
        assert "storage_accounts" in {r[0] for r in rows}

    async def test_the_summary_separates_failure_from_truncation(
        self, replay, connected_account
    ) -> None:
        """The distinction the flat error map could not make. One is an outage;
        the other is a tenant larger than one scan reads, and they call for
        different actions."""
        from app.services.scans import collection_status

        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
            status = await collection_status(session, scan)

        assert status["total"] > 0
        assert status["complete"] == status["total"]
        assert status["partial"] == 0
        assert status["failed"] == 0
        assert status["degraded_categories"] == []

    async def test_each_reading_names_the_subscription_it_came_from(
        self, replay, connected_tenant
    ) -> None:
        from app.services.scans import collection_status

        org_id, connection_id = connected_tenant
        scan_id = await run_connection_scan(org_id, connection_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
            status = await collection_status(session, scan)

        named = {t["subscription"] for t in status["tasks"]}
        # The directory is a reading like any other and appears beside them,
        # named for what it is a reading *of*. Reporting it under a subscription
        # would send someone to check one that is working, and leaving it out
        # would hide the identity checks' coverage entirely.
        assert named == {"Subscription 1", "Subscription 2", DIRECTORY_LABEL}

        directory = [t for t in status["tasks"] if t["subscription"] == DIRECTORY_LABEL]
        assert directory, "the tenant directory reading is missing"
        assert all(t["cloud_account_id"] is None for t in directory)
        assert {t["category"] for t in directory} == {"identity"}

    async def test_readings_are_kept_per_subscription_not_merged(
        self, replay, connected_tenant
    ) -> None:
        """Two subscriptions reading the same listing are two facts, and
        collapsing them would lose which one to go and look at."""
        org_id, connection_id = connected_tenant
        scan_id = await run_connection_scan(org_id, connection_id)

        rows = await fetch(
            "SELECT count(*) FROM evidence "
            "WHERE scan_id = :s AND evidence_key = 'storage_accounts'",
            {"s": scan_id},
        )
        assert rows[0][0] == 2

    async def test_deleting_a_scan_takes_its_readings_with_it(
        self, replay, connected_account
    ) -> None:
        """Unlike findings, these are statements about a run rather than about
        the environment, so they belong to the run."""
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
            await session.delete(scan)
            await session.commit()

        rows = await fetch(
            "SELECT count(*) FROM evidence WHERE scan_id = :s",
            {"s": scan_id},
        )
        assert rows[0][0] == 0


class TestAbandonedScans:
    """A scan whose worker died must not lock its connection out for ever.

    The bug: every non-terminal status counts as a scan in flight, so a row left
    in DISCOVERING by a redeployed worker made that connection answer 409 to
    every future scan, with no timeout and no way out short of editing the
    database.
    """

    async def _make_scan(
        self,
        org_id: uuid.UUID,
        account_id: uuid.UUID,
        *,
        status: ScanStatus,
        lease_until,
        created_at=None,
    ) -> uuid.UUID:
        async with service_session() as session:
            scan = Scan(
                organization_id=org_id,
                cloud_account_id=account_id,
                status=status,
                lease_until=lease_until,
            )
            session.add(scan)
            await session.commit()
            scan_id = scan.id

            if created_at is not None:
                # Set separately: created_at has a server default, so it cannot
                # be backdated on the insert.
                await session.execute(
                    text("UPDATE scans SET created_at = :t WHERE id = :s"),
                    {"t": created_at, "s": scan_id},
                )
                await session.commit()
        return scan_id

    async def test_a_scan_whose_lease_expired_is_closed(
        self, connected_account
    ) -> None:
        org_id, account_id = connected_account
        scan_id = await self._make_scan(
            org_id,
            account_id,
            status=ScanStatus.DISCOVERING,
            lease_until=datetime.now(UTC) - timedelta(minutes=5),
        )

        async with service_session() as session:
            closed = await scans_service.reap_abandoned_scans(session)

        assert scan_id in {sid for sid, _ in closed}
        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
        assert scan.status == ScanStatus.FAILED
        assert "stopped reporting" in scan.error_message
        assert scan.completed_at is not None

    async def test_a_running_scan_with_a_live_lease_is_left_alone(
        self, connected_account
    ) -> None:
        """The lease is the whole safeguard against reaping working scans."""
        org_id, account_id = connected_account
        scan_id = await self._make_scan(
            org_id,
            account_id,
            status=ScanStatus.EVALUATING,
            lease_until=datetime.now(UTC) + timedelta(minutes=10),
        )

        async with service_session() as session:
            closed = await scans_service.reap_abandoned_scans(session)

        assert scan_id not in {sid for sid, _ in closed}
        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
        assert scan.status == ScanStatus.EVALUATING

    async def test_a_scan_queued_past_the_grace_period_is_closed(
        self, connected_account
    ) -> None:
        """No lease, because nothing ever claimed it. Judged on how long it has
        waited instead, and told plainly that no worker collected it."""
        org_id, account_id = connected_account
        scan_id = await self._make_scan(
            org_id,
            account_id,
            status=ScanStatus.QUEUED,
            lease_until=None,
            created_at=datetime.now(UTC)
            - timedelta(seconds=Scan.QUEUE_GRACE_SECONDS + 60),
        )

        async with service_session() as session:
            await scans_service.reap_abandoned_scans(session)
            scan = await session.get(Scan, scan_id)

        assert scan.status == ScanStatus.FAILED
        assert "never picked up" in scan.error_message

    async def test_a_freshly_queued_scan_survives(self, connected_account) -> None:
        """A deep queue is normal. Reaping a scan that was about to start would
        be a worse bug than the one this fixes."""
        org_id, account_id = connected_account
        scan_id = await self._make_scan(
            org_id, account_id, status=ScanStatus.QUEUED, lease_until=None
        )

        async with service_session() as session:
            await scans_service.reap_abandoned_scans(session)
            scan = await session.get(Scan, scan_id)

        assert scan.status == ScanStatus.QUEUED

    async def test_reaping_releases_the_connection(self, connected_account) -> None:
        """The point of the whole exercise, stated as the customer would feel it:
        the scan button works again."""
        org_id, account_id = connected_account
        await self._make_scan(
            org_id,
            account_id,
            status=ScanStatus.DISCOVERING,
            lease_until=datetime.now(UTC) - timedelta(minutes=5),
        )

        async with service_session() as session:
            account = await session.get(CloudAccount, account_id)
            blocked = await scans_service.scan_in_flight(
                session, org_id, account.connection_id, account_id
            )
            assert blocked, "the stuck scan should block before it is reaped"

            await scans_service.reap_abandoned_scans(session)
            still_blocked = await scans_service.scan_in_flight(
                session, org_id, account.connection_id, account_id
            )

        assert not still_blocked

    async def test_a_finished_scan_is_never_reaped(
        self, replay, connected_account
    ) -> None:
        """However stale its lease column looks."""
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        async with service_session() as session:
            await session.execute(
                text("UPDATE scans SET lease_until = :t WHERE id = :s"),
                {"t": datetime.now(UTC) - timedelta(days=1), "s": scan_id},
            )
            await session.commit()
            closed = await scans_service.reap_abandoned_scans(session)

        assert scan_id not in {sid for sid, _ in closed}

    async def test_a_running_scan_holds_a_lease(self, replay, connected_account) -> None:
        """And releases it when it finishes, so the reaper's index carries only
        work that is actually outstanding."""
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)

        assert scan.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
        assert scan.lease_until is None


class TestScanScope:
    """A scan reads what it covers, not what the tenant owns.

    ``_persist_findings`` used to select every finding in the organization,
    its risk links every link, and ``_persist_relationships`` the whole edge
    table -- on every scan, including a rescan of one finding in a tenant of
    fifty subscriptions. The scope predicate replaced all three, and the arm
    that needed the most care is the one for findings with no resource at all.
    """

    async def test_an_aggregate_finding_is_not_duplicated_by_a_second_scan(
        self, replay, connected_account
    ) -> None:
        """AZ-ID-002 is AGGREGATE, so its finding carries no resource.

        The scope is expressed over the asset a finding is about, so a finding
        without one has to be admitted explicitly. Miss that and the second
        scan cannot see the first scan's row -- it inserts a rival for a key the
        unique index already holds, and the scan fails with an IntegrityError
        reported to the customer as nothing in particular.
        """
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        first = await fetch(
            "SELECT count(*) FROM findings "
            "WHERE organization_id = :o AND resource_id IS NULL",
            {"o": org_id},
        )

        await run_scan(org_id, account_id)
        second = await fetch(
            "SELECT count(*) FROM findings "
            "WHERE organization_id = :o AND resource_id IS NULL",
            {"o": org_id},
        )

        assert first[0][0] == second[0][0], (
            "a re-detected aggregate finding updates its row rather than adding one"
        )

    async def test_a_scan_leaves_another_connection_alone(
        self, replay, connected_account, connected_tenant
    ) -> None:
        """Two connections in two organizations, one scanned.

        The scope is what states the intent; before it, isolation rested on the
        accident that a resource id from one tenant could not match a key from
        another.
        """
        other_org, connection_id = connected_tenant
        await run_connection_scan(other_org, connection_id)
        before = await fetch(
            "SELECT count(*) FROM findings WHERE organization_id = :o",
            {"o": other_org},
        )

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        after = await fetch(
            "SELECT count(*) FROM findings WHERE organization_id = :o",
            {"o": other_org},
        )
        assert before == after


class TestEvidence:
    """One row per reading, one stored copy of what it produced."""

    async def test_a_successful_reading_is_recorded_with_its_payload(
        self, replay, connected_account
    ) -> None:
        """The half that was missing. The ledger recorded failures; a success
        left nothing behind but data inside a blob nothing could point at."""
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT evidence_key, content_hash, byte_size FROM evidence "
            "WHERE scan_id = :s AND outcome = 'COMPLETE'",
            {"s": scan_id},
        )
        assert rows, "a completed scan records what it read"
        for key, content_hash, byte_size in rows:
            assert content_hash is not None, f"{key} recorded no payload"
            assert len(content_hash) == 64
            assert byte_size > 0

    # Permissions are recorded from the plan's own declaration, which the
    # recorded fixture predates -- so the assertion that a reading carries them
    # lives in tests/unit/test_evidence_store.py, against a real coverage
    # report rather than against a recording that could only echo whatever was
    # written into it.

    async def test_an_unchanged_environment_stores_its_payloads_once(
        self, replay, connected_account
    ) -> None:
        """The reason the payloads are content-addressed.

        A customer scanning daily whose environment has not changed stored the
        whole thing again every time. Scanning the same recording twice must add
        evidence rows and no new payloads at all.
        """
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        after_first = await fetch(
            "SELECT count(*) FROM evidence_blobs WHERE organization_id = :o",
            {"o": org_id},
        )

        await run_scan(org_id, account_id)
        after_second = await fetch(
            "SELECT count(*) FROM evidence_blobs WHERE organization_id = :o",
            {"o": org_id},
        )
        evidence_rows = await fetch(
            "SELECT count(*) FROM evidence WHERE organization_id = :o",
            {"o": org_id},
        )

        assert after_first[0][0] == after_second[0][0], "identical bytes stored twice"
        assert evidence_rows[0][0] > after_second[0][0], (
            "the second scan should still record that it read everything again"
        )

    async def test_re_reading_the_same_payload_touches_it(
        self, replay, connected_account
    ) -> None:
        """What retention reads. A payload still being collected must not look
        like one whose last reference was months ago."""
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        first = await fetch(
            "SELECT max(last_seen_at), max(first_stored_at) FROM evidence_blobs "
            "WHERE organization_id = :o",
            {"o": org_id},
        )

        await run_scan(org_id, account_id)
        second = await fetch(
            "SELECT max(last_seen_at), max(first_stored_at) FROM evidence_blobs "
            "WHERE organization_id = :o",
            {"o": org_id},
        )

        assert second[0][0] >= first[0][0], "last_seen_at went backwards"
        assert second[0][1] == first[0][1], "first_stored_at is not the storing time"

    async def test_a_failed_reading_points_at_no_payload(
        self, replay, connected_account
    ) -> None:
        """A hash of nothing would claim there was something to point at."""
        org_id, account_id = connected_account
        replay["payload"]["errors"]["storage"] = "Azure API timeout"
        scan_id = await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT content_hash, byte_size FROM evidence "
            "WHERE scan_id = :s AND outcome <> 'COMPLETE'",
            {"s": scan_id},
        )
        assert rows, "the injected failure should have been recorded"
        for content_hash, byte_size in rows:
            assert content_hash is None
            assert byte_size == 0

    async def test_evidence_records_when_the_provider_was_read(
        self, replay, connected_account
    ) -> None:
        """``collected_at``, not the row's write time. The two are the same for
        a live scan and months apart for a replay, and freshness is about the
        first."""
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT count(*) FROM evidence "
            "WHERE scan_id = :s AND collected_at IS NOT NULL",
            {"s": scan_id},
        )
        assert rows[0][0] > 0


class TestOrchestration:
    """A scan is durable steps, not one task that must survive everything.

    The bug this replaces: a worker redeployed after reading nine subscriptions
    out of ten had read nothing, because nothing recorded that the nine were
    done. Migration 0009 made that detectable; steps make it survivable.
    """

    async def _steps(self, scan_id: uuid.UUID) -> list[ScanStep]:
        async with service_session() as session:
            return await orchestrator.steps_for(session, scan_id)

    async def test_a_scan_records_a_step_per_scope(
        self, replay, connected_tenant
    ) -> None:
        org_id, connection_id = connected_tenant
        scan_id = await run_connection_scan(org_id, connection_id)

        steps = await self._steps(scan_id)
        kinds = [s.kind for s in steps]
        assert kinds.count(ScanStepKind.PLAN) == 1
        assert kinds.count(ScanStepKind.ANALYZE) == 1
        # Two subscriptions plus the tenant directory.
        assert kinds.count(ScanStepKind.COLLECT) == 3
        assert all(s.status == ScanStepStatus.SUCCEEDED for s in steps)

    async def test_a_claimed_step_cannot_be_claimed_twice(
        self, replay, connected_account
    ) -> None:
        """The concurrency control, exercised where it can actually race.

        Two advances arriving together must split the work rather than hand the
        same subscription to two workers -- which would collect it twice and
        write two captures for one reading.
        """
        org_id, account_id = connected_account
        async with service_session() as session:
            scan = Scan(
                organization_id=org_id,
                cloud_account_id=account_id,
                status=ScanStatus.QUEUED,
            )
            session.add(scan)
            await session.commit()
            scan_id = scan.id
            await orchestrator.create_initial_steps(session, scan)
            await session.commit()

        async with service_session() as session:
            steps = await orchestrator.steps_for(session, scan_id)
            ids = [s.id for s in orchestrator.runnable(steps)]
            first = await orchestrator.claim(session, ids)

        async with service_session() as session:
            second = await orchestrator.claim(session, ids)

        assert first, "the first advance should have won the step"
        assert second == [], "a claimed step must not be handed out again"

    async def test_a_scan_resumes_after_its_worker_disappears(
        self, replay, connected_account
    ) -> None:
        """The whole point of the exercise.

        A step whose lease expired goes back to PENDING and the next advance
        runs it -- so a redeploy costs the step in flight rather than the scan,
        and the customer does not run the whole thing again.
        """
        org_id, account_id = connected_account
        async with service_session() as session:
            scan = Scan(
                organization_id=org_id,
                cloud_account_id=account_id,
                status=ScanStatus.QUEUED,
            )
            session.add(scan)
            await session.commit()
            scan_id = scan.id
            await orchestrator.create_initial_steps(session, scan)
            await session.commit()

        # Claim the PLAN step and then vanish, exactly as a killed worker does.
        async with service_session() as session:
            steps = await orchestrator.steps_for(session, scan_id)
            plan = next(s for s in steps if s.kind == ScanStepKind.PLAN)
            await orchestrator.claim(session, [plan.id])
            await session.execute(
                text("UPDATE scan_steps SET lease_until = :t WHERE id = :s"),
                {"t": datetime.now(UTC) - timedelta(minutes=30), "s": plan.id},
            )
            await session.commit()

        async with service_session() as session:
            reclaimed = await orchestrator.reap_expired_steps(session)
        assert scan_id in reclaimed

        async with service_session() as session:
            refreshed = await orchestrator.steps_for(session, scan_id)
            plan = next(s for s in refreshed if s.kind == ScanStepKind.PLAN)
        assert plan.status == ScanStepStatus.PENDING
        assert plan.attempt == 1, "the attempt is spent, not forgotten"

        # And the scan runs to completion from where it was.
        await drive(scan_id)
        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
        assert scan.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)

    async def test_a_reaped_step_is_not_a_reaped_scan(
        self, replay, connected_account
    ) -> None:
        """A scan with a step waiting for a worker has work outstanding, not
        work nobody is doing -- and closing it would close a scan that is about
        to continue."""
        org_id, account_id = connected_account
        async with service_session() as session:
            scan = Scan(
                organization_id=org_id,
                cloud_account_id=account_id,
                status=ScanStatus.DISCOVERING,
            )
            session.add(scan)
            await session.commit()
            scan_id = scan.id
            await orchestrator.create_initial_steps(session, scan)
            await session.commit()
            # Old enough that the queue grace period has elapsed.
            await session.execute(
                text("UPDATE scans SET created_at = :t WHERE id = :s"),
                {
                    "t": datetime.now(UTC)
                    - timedelta(seconds=Scan.QUEUE_GRACE_SECONDS + 60),
                    "s": scan_id,
                },
            )
            await session.commit()

        async with service_session() as session:
            closed = await scans_service.reap_abandoned_scans(session)

        assert scan_id not in {sid for sid, _ in closed}

    async def test_a_scan_with_nothing_to_read_skips_its_analysis(
        self, replay, connected_tenant
    ) -> None:
        """Otherwise it would hang rather than fail: ANALYZE waits on
        collection, collection waits on a PLAN that gave up, and nothing is left
        to move."""
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

        steps = await self._steps(scan_id)
        plan = next(s for s in steps if s.kind == ScanStepKind.PLAN)
        analyze = next(s for s in steps if s.kind == ScanStepKind.ANALYZE)
        assert plan.status == ScanStepStatus.FAILED
        assert analyze.status == ScanStepStatus.SKIPPED, (
            "a step whose dependency gave up is skipped, not left pending forever"
        )

    async def test_one_unreadable_subscription_does_not_withhold_the_report(
        self, replay, connected_tenant
    ) -> None:
        """Settled, not succeeded. Nine subscriptions out of ten is nine
        subscriptions' worth of findings and one recorded gap."""
        org_id, connection_id = connected_tenant
        async with service_session() as session:
            scan = Scan(
                organization_id=org_id,
                connection_id=connection_id,
                status=ScanStatus.QUEUED,
            )
            session.add(scan)
            await session.commit()
            scan_id = scan.id
            await orchestrator.create_initial_steps(session, scan)
            await session.commit()

        # Run PLAN, then fail one subscription outright before the rest run.
        async with service_session() as session:
            steps = await orchestrator.steps_for(session, scan_id)
            plan = next(s for s in steps if s.kind == ScanStepKind.PLAN)
            await orchestrator.claim(session, [plan.id])
        await ScanPipeline(scan_id).run_step(plan.id)

        async with service_session() as session:
            steps = await orchestrator.steps_for(session, scan_id)
            doomed = next(
                s
                for s in steps
                if s.kind == ScanStepKind.COLLECT and s.cloud_account_id is not None
            )
            doomed.status = ScanStepStatus.FAILED
            doomed.error = "Forbidden"
            doomed.finished_at = datetime.now(UTC)
            await session.commit()

        await drive(scan_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
        assert scan.status == ScanStatus.PARTIAL, "a gap is a report, not a failure"
        assert scan.finding_count > 0, "the readable subscriptions still produced findings"
        assert "Forbidden" in (scan.error_message or "")

    async def test_starting_a_scan_twice_does_not_duplicate_its_steps(
        self, replay, connected_account
    ) -> None:
        """A broker that redelivers the start message must not fail the scan.

        The regression: an acknowledgement lost, or a worker killed between
        running the start task and acking it, inserted a second PLAN, hit the
        unique index, and failed the start of a scan that had already started
        correctly.
        """
        org_id, account_id = connected_account
        async with service_session() as session:
            scan = Scan(
                organization_id=org_id,
                cloud_account_id=account_id,
                status=ScanStatus.QUEUED,
            )
            session.add(scan)
            await session.commit()
            scan_id = scan.id

            first = await orchestrator.create_initial_steps(session, scan)
            await session.commit()
            second = await orchestrator.create_initial_steps(session, scan)
            await session.commit()

        assert len(first) == 2
        assert second == [], "a redelivered start creates nothing new"
        steps = await self._steps(scan_id)
        assert len(steps) == 2

    async def test_a_redelivered_start_does_not_reset_a_failing_step(
        self, replay, connected_account
    ) -> None:
        """Attempts are spent, not forgotten. Otherwise a step that fails every
        time would be retried for ever, one redelivery at a time."""
        org_id, account_id = connected_account
        async with service_session() as session:
            scan = Scan(
                organization_id=org_id,
                cloud_account_id=account_id,
                status=ScanStatus.QUEUED,
            )
            session.add(scan)
            await session.commit()
            scan_id = scan.id
            await orchestrator.create_initial_steps(session, scan)
            await session.commit()

            steps = await orchestrator.steps_for(session, scan_id)
            plan = next(s for s in steps if s.kind == ScanStepKind.PLAN)
            await orchestrator.claim(session, [plan.id])

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
            await orchestrator.create_initial_steps(session, scan)
            await session.commit()
            steps = await orchestrator.steps_for(session, scan_id)

        plan = next(s for s in steps if s.kind == ScanStepKind.PLAN)
        assert plan.attempt == 1
        assert plan.status == ScanStepStatus.RUNNING

    async def test_a_scan_that_read_everything_but_lost_a_listing_is_partial(
        self, replay, connected_account
    ) -> None:
        """A step succeeded and the scan is still degraded.

        The COLLECT step did its job: it collected, and it recorded that the
        storage listing was unreadable. Deriving the scan's status from the
        steps alone reported COMPLETED over a rule that had lost its verdict.
        """
        org_id, account_id = connected_account
        replay["payload"]["errors"]["storage"] = "Azure API timeout"
        scan_id = await run_scan(org_id, account_id)

        steps = await self._steps(scan_id)
        assert all(s.status == ScanStepStatus.SUCCEEDED for s in steps), (
            "no step failed -- the gap is inside a successful reading"
        )

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
        assert scan.status == ScanStatus.PARTIAL
        assert "storage" in scan.collection_errors
