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
    RuleState,
    ScanStatus,
    ScanStepKind,
    ScanStepStatus,
    ScanTrigger,
    TaskOutcome,
    VerificationStatus,
)
from app.models.cloud_account import CloudAccount
from app.models.context import ContextDeclarationRecord
from app.models.finding import Finding
from app.models.scan import Scan, ScanStep
from app.models.verification import RemediationVerification
from app.services import orchestrator
from app.services import scanner as scanner_module
from app.services import scans as scans_service
from app.services import verification as verification_service
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
        self.plans: list = []
        self._normalizer = AzureNormalizer()

    async def validate_connection(self):  # pragma: no cover -- not used here
        raise NotImplementedError

    async def collect(self, on_progress=None, plan=None) -> RawSnapshot:
        # The plan is accepted and ignored: a recording has already been
        # collected, so there is nothing to narrow and nothing to carry. What
        # the double must do is take the argument, because the pipeline passes
        # one to every connector.
        self.plans.append(plan)
        if on_progress:
            await on_progress(1, 1)
        return self._slice(directory=False)

    async def collect_directory(self, on_progress=None, plan=None) -> RawSnapshot:
        self.plans.append(plan)
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
        for step_id, _kind in claimed:
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
                            # Finding risks. A scenario is also joined to its
                            # members through this junction and is scored by a
                            # different formula -- floored at its worst member
                            # rather than weighted across six components -- so
                            # asserting the components on one would be checking
                            # working that was never done.
                            "WHERE r.organization_id = :o AND r.kind = 'FINDING'"
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

    async def test_a_reading_says_what_rests_on_it(
        self, replay, connected_account
    ) -> None:
        """The citation chain walked from the evidence end.

        The finding page asks where its evidence came from. A person looking at
        a listing on the scans page has the mirror question -- what did this
        reading actually support -- and the count has to be followable to
        exactly those findings, which is why the reading's own id is exposed
        beside it rather than only its key.
        """
        from app.services.scans import collection_status

        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
            status = await collection_status(session, scan)

        cited = [t for t in status["tasks"] if t["finding_count"] > 0]
        assert cited, "no reading was reported as supporting any finding"

        for task in status["tasks"]:
            assert task["evidence_id"], "a count with no way to follow it"
            assert task["collected_at"]

        # The count and the filter must name the same set, or the number stops
        # surviving being clicked.
        for task in cited:
            rows = await fetch(
                "SELECT count(DISTINCT finding_id) FROM finding_evidence "
                "WHERE organization_id = :o AND evidence_id = :e",
                {"o": org_id, "e": task["evidence_id"]},
            )
            assert rows[0][0] == task["finding_count"]

    # What a reading *called* is recorded from the plan's own declaration, and
    # the recorded fixture predates it -- exactly as it predates `permissions`,
    # noted in TestEvidence above for the same reason. A recording can only echo
    # what was written into it, so asserting here would be this file checking
    # its own fixture. The declaration lives in
    # tests/unit/test_provider_endpoints.py and its journey into an evidence row
    # in tests/unit/test_evidence_store.py, both against a real plan.

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

    async def test_one_subscription_names_its_gaps_plainly(
        self, replay, connected_account
    ) -> None:
        """No qualifier where there is nothing to disambiguate.

        The regression: the qualifier was applied whenever a scan held more than
        one *capture*, and a scan now stores a directory capture beside the
        subscription's. A customer with a single subscription saw
        "00000000-0000-0000-0000-000000000001: storage" on the one screen whose
        job is to be readable.
        """
        org_id, account_id = connected_account
        replay["payload"]["errors"]["storage"] = "Azure API timeout"
        scan_id = await run_scan(org_id, account_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)

        assert "storage" in scan.collection_errors
        assert not any(":" in key for key in scan.collection_errors), (
            f"a single-subscription scan qualified its gaps: {scan.collection_errors}"
        )

    async def test_several_subscriptions_still_name_theirs(
        self, replay, connected_tenant
    ) -> None:
        """The other half of the same rule. Two subscriptions can both fail to
        read storage, and "storage: timeout" twice over tells a customer nothing
        about which one to go and look at."""
        org_id, connection_id = connected_tenant
        replay["payload"]["errors"]["storage"] = "Azure API timeout"
        scan_id = await run_connection_scan(org_id, connection_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)

        qualified = [key for key in scan.collection_errors if key.endswith(": storage")]
        assert len(qualified) == 2, scan.collection_errors
        assert {"Subscription 1: storage", "Subscription 2: storage"} == set(qualified)

    async def test_a_finished_scan_can_say_where_its_time_went(
        self, replay, connected_tenant
    ) -> None:
        """"Why was this scan slow?" had no answer.

        A scan was one task with one start and one end, so a slow subscription
        and a slow evaluation looked identical. Steps record when each stage was
        claimed and when it settled as a side effect of being durable, so the
        question is answerable from rows already being written.
        """
        from app.services.scans import scan_stages

        org_id, connection_id = connected_tenant
        scan_id = await run_connection_scan(org_id, connection_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
            stages = await scan_stages(session, scan)

        assert {s["stage"] for s in stages} == {"PLAN", "COLLECT", "ANALYZE"}
        assert all(s["duration_seconds"] is not None for s in stages), (
            "a settled stage knows how long it took"
        )
        assert all(s["status"] == "SUCCEEDED" for s in stages)

        # Named for the scope, not the row: a customer wants to know which
        # subscription was slow, not which UUID.
        collect_scopes = {s["scope"] for s in stages if s["stage"] == "COLLECT"}
        assert collect_scopes == {"Subscription 1", "Subscription 2", DIRECTORY_LABEL}

    async def test_a_stage_reports_the_attempt_it_took(
        self, replay, connected_account
    ) -> None:
        """A step on its second attempt is a step that was interrupted, which is
        the first thing to know about a scan that took twice as long as usual."""
        from app.services.scans import scan_stages

        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
            stages = await scan_stages(session, scan)

        assert all(s["attempt"] == 1 for s in stages), (
            "an uninterrupted scan took one attempt per stage"
        )


class TestScheduling:
    """Which connections are overdue a reading, and what starting one does.

    The decision is a query over the newest scan per connection, so it needs a
    real database: the interval arithmetic, the never-scanned case and the
    ordering are all things SQL does and a fake would only restate.
    """

    async def _set_interval(self, connection_id: uuid.UUID, hours: int | None) -> None:
        async with service_session() as session:
            await session.execute(
                text(
                    "UPDATE cloud_connections SET scan_interval_hours = :h "
                    "WHERE id = :c"
                ),
                {"h": hours, "c": connection_id},
            )
            await session.commit()

    async def _due(self) -> set[uuid.UUID]:
        async with service_session() as session:
            due = await scans_service.connections_due(session, limit=50)
        return {c.id for c in due}

    async def test_an_unscheduled_connection_is_never_due(
        self, replay, connected_tenant
    ) -> None:
        """Every connection starts this way, and stays this way until asked."""
        _org_id, connection_id = connected_tenant
        assert connection_id not in await self._due()

    async def test_a_scheduled_connection_that_has_never_scanned_is_due_now(
        self, replay, connected_tenant
    ) -> None:
        """What somebody who just switched scheduling on expects to happen.

        It falls out of the interval arithmetic rather than being special-cased:
        a connection with no scan has nothing to measure an interval from, so it
        is overdue by definition.
        """
        _org_id, connection_id = connected_tenant
        await self._set_interval(connection_id, 24)
        assert connection_id in await self._due()

    async def test_a_recently_scanned_connection_is_not_due(
        self, replay, connected_tenant
    ) -> None:
        org_id, connection_id = connected_tenant
        await self._set_interval(connection_id, 24)
        await run_connection_scan(org_id, connection_id)

        assert connection_id not in await self._due()

    async def test_a_connection_becomes_due_once_its_interval_has_elapsed(
        self, replay, connected_tenant
    ) -> None:
        """Measured from when the last scan *started*.

        From when it finished, a scan that takes forty minutes would push the
        next one forty minutes later every time, and a daily scan would drift
        into an every-other-day one.
        """
        org_id, connection_id = connected_tenant
        await self._set_interval(connection_id, 24)
        scan_id = await run_connection_scan(org_id, connection_id)

        async with service_session() as session:
            await session.execute(
                text("UPDATE scans SET created_at = :t WHERE id = :s"),
                {"t": datetime.now(UTC) - timedelta(hours=25), "s": scan_id},
            )
            await session.commit()

        assert connection_id in await self._due()

    async def test_turning_scheduling_off_stops_it(
        self, replay, connected_tenant
    ) -> None:
        _org_id, connection_id = connected_tenant
        await self._set_interval(connection_id, 24)
        assert connection_id in await self._due()

        await self._set_interval(connection_id, None)
        assert connection_id not in await self._due()

    async def test_a_scheduled_scan_says_it_was_scheduled(
        self, replay, connected_tenant
    ) -> None:
        """A NULL user could not carry this once scans could start themselves:
        a manual scan whose user record had gone looked identical."""
        org_id, connection_id = connected_tenant
        async with service_session() as session:
            scan = Scan(
                organization_id=org_id,
                connection_id=connection_id,
                status=ScanStatus.QUEUED,
                trigger=ScanTrigger.SCHEDULED,
            )
            session.add(scan)
            await session.commit()
            scan_id = scan.id

        async with service_session() as session:
            stored = await session.get(Scan, scan_id)
        assert stored.trigger == ScanTrigger.SCHEDULED
        assert stored.triggered_by_user_id is None

    async def test_a_manual_scan_still_says_manual(
        self, replay, connected_account
    ) -> None:
        """The default, so nothing that predates the column is mislabelled."""
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
        assert scan.trigger == ScanTrigger.MANUAL

    async def test_the_scheduler_does_not_pile_a_scan_on_a_running_one(
        self, replay, connected_tenant
    ) -> None:
        """The interval is a floor on how often the environment is read, not an
        instruction to stack scans on top of each other."""
        org_id, connection_id = connected_tenant
        await self._set_interval(connection_id, 24)

        async with service_session() as session:
            session.add(
                Scan(
                    organization_id=org_id,
                    connection_id=connection_id,
                    status=ScanStatus.DISCOVERING,
                )
            )
            await session.commit()

            in_flight = await scans_service.scan_in_flight(
                session, org_id, connection_id, None
            )
        assert in_flight, "the scheduler's own guard should see this one"


class TestAssetGraph:
    """The graph, rebuilt from what a real scan persisted.

    The unit tests prove the traversal and prove the normalizer produces the
    right shape. What is left is whether the edges survive the round trip
    through PostgreSQL — an edge is stored by database id and the graph works
    in provider ids, and a mapping that dropped one would leave a path
    silently short.
    """

    async def test_a_scan_persists_the_capability_edges(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT relationship_type, count(*) FROM resource_relationships "
            "WHERE organization_id = :o GROUP BY relationship_type",
            {"o": org_id},
        )
        kinds = dict(rows)

        assert kinds.get("has_identity", 0) == 1, "the VM runs as its identity"
        assert kinds.get("grants_role", 0) == 1, "that identity holds a role"
        assert kinds.get("contains", 0) > 0, "and everything sits somewhere"

    async def test_the_path_survives_the_round_trip(
        self, replay, connected_account
    ) -> None:
        """Built from the database rather than from the scan's own memory."""
        from app.services import graph as graph_service

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            graph = await graph_service.load_graph(session, org_id)

        paths = graph.attack_paths()
        assert paths, "an internet-facing VM reaching sensitive data"
        assert all(p.entry.name == "vm-jumpbox" for p in paths)
        assert all(p.cheapest_break() is not None for p in paths)

    async def test_the_blast_radius_of_the_jump_box_identity(
        self, replay, connected_account
    ) -> None:
        """What would go if that host were taken."""
        from app.services import graph as graph_service

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            graph = await graph_service.load_graph(session, org_id)

        principal = next(
            node_id
            for node_id, node in graph.nodes.items()
            if node.resource_type.value == "service_principal"
        )
        reached = graph.blast_radius(principal)

        assert reached, "Contributor over the subscription reaches its contents"
        # Scopes are where the reach lands; the assets beneath are what it is
        # of. Listing both would count the same authority twice.
        assert all(
            r.resource_type.value not in ("subscription", "resource_group")
            for r in reached
        )

    async def test_an_edge_outliving_its_resource_is_not_followed(
        self, replay, connected_account
    ) -> None:
        """A route through something that has been deleted is not a shorter
        route, it is a description of an environment that no longer exists."""
        from app.services import graph as graph_service

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            # Delete the principal out from under its edges. ON DELETE CASCADE
            # takes the edges too, which is the behaviour being confirmed —
            # the loader's own guard is the belt to that braces.
            await session.execute(
                text(
                    "DELETE FROM cloud_resources "
                    "WHERE organization_id = :o AND resource_type = 'service_principal'"
                ),
                {"o": org_id},
            )
            await session.commit()
            graph = await graph_service.load_graph(session, org_id)

        assert graph.attack_paths() == []

    async def test_an_absent_resource_is_not_on_any_route(
        self, replay, connected_account
    ) -> None:
        """The reported bug. An asset a scan looked for and did not find keeps
        its row -- so its findings stay history, and so an asset that vanishes
        for a week and returns is one asset rather than two -- and the loader
        was reading every row the organization had. The attack-paths page
        therefore served routes through resources that were gone, while the
        scanner's own graph, built from one scan's state, never contained them.
        """
        from app.services import graph as graph_service

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            assert await graph_service.load_graph(session, org_id) is not None
            # Not deleted: absent, which is what a scan that covered the scope
            # and did not find it records.
            await session.execute(
                text(
                    "UPDATE cloud_resources SET absent_since = now() "
                    "WHERE organization_id = :o AND resource_type = 'service_principal'"
                ),
                {"o": org_id},
            )
            await session.commit()
            graph = await graph_service.load_graph(session, org_id)

        assert graph.attack_paths() == []
        assert not any(
            node.resource_type.value == "service_principal"
            for node in graph.nodes.values()
        )


class TestRouteProvenance:
    """Which reading a route was seen in.

    A finding has always named the scan that detected it. A route did not, and
    it is the risk kind where the question carries most weight: a path is a
    claim about how an environment is wired, assembled from one scan's
    normalized state, and "this route is open" is only ever true as of a
    reading.

    Without it, a customer who fixed the middle hop this morning cannot tell a
    route that survived the latest scan from one nothing has re-checked since
    Tuesday. The two render identically.
    """

    async def test_a_route_names_the_scan_that_saw_it(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT kind, observed_scan_id FROM risks "
            "WHERE organization_id = :o AND kind <> 'FINDING'",
            {"o": org_id},
        )
        assert rows, "the scan produced no scenario risks to attribute"
        for kind, observed in rows:
            assert observed == scan_id, f"{kind} named no reading"

    async def test_re_observing_a_route_moves_it_to_the_newer_reading(
        self, replay, connected_account
    ) -> None:
        """Written on every observation, not only at creation.

        The useful question about a route is not when it first appeared but
        whether anything has looked since. A value frozen at creation would
        answer the first while looking like the second -- a route last checked
        in March, reported as though it were current.
        """
        org_id, account_id = connected_account
        first = await run_scan(org_id, account_id)

        before = await fetch(
            "SELECT count(*) FROM risks WHERE organization_id = :o "
            "AND observed_scan_id = :s AND kind <> 'FINDING'",
            {"o": org_id, "s": first},
        )
        assert before[0][0] > 0

        second = await run_scan(org_id, account_id)

        stale = await fetch(
            "SELECT count(*) FROM risks WHERE organization_id = :o "
            "AND observed_scan_id = :s AND kind <> 'FINDING'",
            {"o": org_id, "s": first},
        )
        current = await fetch(
            "SELECT count(*) FROM risks WHERE organization_id = :o "
            "AND observed_scan_id = :s AND kind <> 'FINDING'",
            {"o": org_id, "s": second},
        )

        assert stale[0][0] == 0, "a route still names the reading before last"
        assert current[0][0] > 0

    async def test_a_finding_risk_names_no_reading_of_its_own(
        self, replay, connected_account
    ) -> None:
        """It takes its reading from the finding it was scored from.

        Setting it here as well would be a second answer to one question, and
        the two would drift the first time a finding was re-detected by a scan
        that produced no scenario at all.
        """
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT count(*) FROM risks WHERE organization_id = :o "
            "AND kind = 'FINDING' AND observed_scan_id IS NOT NULL",
            {"o": org_id},
        )
        assert rows[0][0] == 0

    async def test_deleting_the_scan_leaves_the_route_standing(
        self, replay, connected_account
    ) -> None:
        """``SET NULL``, because risks outlive scans exactly as findings do.

        The row then says it was seen and no longer which reading saw it, which
        is a worse answer than the full one and a much better one than the route
        disappearing with its scan.
        """
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        before = await fetch(
            "SELECT count(*) FROM risks WHERE organization_id = :o "
            "AND kind <> 'FINDING'",
            {"o": org_id},
        )
        assert before[0][0] > 0

        async with service_session() as session:
            await session.execute(
                text("DELETE FROM scans WHERE id = :s"), {"s": scan_id}
            )
            await session.commit()

        after = await fetch(
            "SELECT count(*), count(observed_scan_id) FROM risks "
            "WHERE organization_id = :o AND kind <> 'FINDING'",
            {"o": org_id},
        )
        assert after[0][0] == before[0][0], "routes were deleted with the scan"
        assert after[0][1] == 0, "the reference should have been nulled"


class TestCaptureReconstruction:
    """Whether the readings add back up to the capture, on real scans.

    ``tests/unit/test_evidence_store.py`` states the precondition: replay reads
    ``cloud_snapshots`` and must keep doing so until reconstruction holds
    against real scans. This is that check, and it is the gate on a change worth
    naming, because the same bytes are currently stored twice.

    ``cloud_snapshots.data`` is a whole capture per scan and is **not**
    deduplicated: a daily scan of an estate that has not changed writes a fresh
    full copy every night. The per-key payloads beside it are content-addressed
    and store one. If the second reconstructs the first, the first is a copy
    the schema is paying for nightly.

    Not a flip, deliberately. The claim is checkable only here, against
    PostgreSQL and a real pipeline run, so the check ships first and the change
    follows it.
    """

    async def test_the_stored_readings_rebuild_the_capture_exactly(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        captures = await fetch(
            "SELECT cloud_account_id, data FROM cloud_snapshots WHERE scan_id = :s",
            {"s": scan_id},
        )
        assert captures, "the scan stored no capture"

        for cloud_account_id, capture in captures:
            # The payloads this scope actually read, joined back through the
            # hash the evidence row recorded. A directory capture files under a
            # NULL account, which is how Evidence records it too.
            rows = await fetch(
                "SELECT e.evidence_key, b.payload "
                "FROM evidence e JOIN evidence_blobs b "
                "  ON b.content_hash = e.content_hash "
                "WHERE e.scan_id = :s AND e.organization_id = :o "
                "  AND e.cloud_account_id IS NOT DISTINCT FROM :a",
                {"s": scan_id, "o": org_id, "a": cloud_account_id},
            )
            assert rows, "a capture whose readings stored nothing"

            # Merged by payload rather than keyed by task, and that is the
            # case a careless flip gets wrong: one task can produce several
            # payload keys. ``authentication_methods`` has no task of its own --
            # the directory's role-map task reads it -- so a reconstruction that
            # assumed one key per task would drop it silently, and the MFA rule
            # would then find nothing to judge.
            rebuilt: dict = {}
            for _key, payload in rows:
                rebuilt.update(payload)

            assert rebuilt == capture["data"], (
                "the readings do not add back up to the capture, so evidence "
                "cannot replace it: whatever differs would be silently dropped"
            )

    async def test_an_unchanged_estate_stores_one_payload_set_and_many_captures(
        self, replay, connected_account
    ) -> None:
        """The cost this measures, stated as a test rather than as an estimate.

        Scanning the same recording twice must add no payloads at all --
        content addressing already sees to that -- while adding a second whole
        capture. That gap is the duplication, and it grows once per scan for as
        long as retention keeps the captures.
        """
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        blobs_after_one = await fetch(
            "SELECT count(*), coalesce(sum(byte_size), 0) FROM evidence_blobs "
            "WHERE organization_id = :o",
            {"o": org_id},
        )

        await run_scan(org_id, account_id)
        blobs_after_two = await fetch(
            "SELECT count(*), coalesce(sum(byte_size), 0) FROM evidence_blobs "
            "WHERE organization_id = :o",
            {"o": org_id},
        )
        captures = await fetch(
            "SELECT count(*) FROM cloud_snapshots WHERE organization_id = :o",
            {"o": org_id},
        )

        assert blobs_after_two == blobs_after_one, "payloads were stored twice"
        assert captures[0][0] > 1, "captures are not deduplicated, and are not here"


class TestGraphCaching:
    """The cache is keyed on a version, so the version has to actually move.

    The unit tests hold the caching logic. What only a real database can settle
    is the premise underneath it: that a scan changes what ``graph_version``
    reports. If it did not, the attack-path pages would serve the estate as it
    was the first time anybody looked at them, indefinitely, and nothing would
    say so.
    """

    async def test_a_scan_changes_the_version_the_graph_is_keyed_on(
        self, replay, connected_account
    ) -> None:
        from app.services import graph as graph_service

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            before = await graph_service.graph_version(session, org_id)

        # A second reading of a changed environment: assets are rewritten, and
        # the version must move with them.
        await run_scan(org_id, account_id)

        async with service_session() as session:
            after = await graph_service.graph_version(session, org_id)

        assert before != after, (
            "a scan left the graph version unchanged, so cached attack paths "
            "would outlive the estate they describe"
        )

    async def test_the_version_is_stable_when_nothing_has_scanned(
        self, replay, connected_account
    ) -> None:
        """Otherwise the cache would never hit and the whole thing is dead
        weight that costs an extra query per request."""
        from app.services import graph as graph_service

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            first = await graph_service.graph_version(session, org_id)
            second = await graph_service.graph_version(session, org_id)

        assert first == second


class TestChokePoints:
    """Which single change closes the most routes.

    The list ranks routes, which is right for reading and wrong for acting. This
    is the other half, and the number has to be the verified one: a customer
    told four routes close who then sees two remain stops believing the next
    number too.
    """

    async def test_the_link_it_names_really_does_close_those_routes(
        self, replay, connected_account
    ) -> None:
        from app.services import graph as graph_service

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            graph = await graph_service.load_graph(session, org_id)

        routes = graph.attack_paths()
        assert routes, "the fixture estate has a route"

        for choke in graph.choke_points():
            # The claim, re-checked against the graph it was made about.
            pruned = graph._without(
                (
                    choke.step.source.provider_resource_id,
                    choke.step.relationship.value,
                    choke.step.target.provider_resource_id,
                )
            )
            assert len(pruned.attack_paths()) == len(routes) - choke.severs
            assert choke.severs <= choke.on_routes

    async def test_asking_does_not_change_the_graph(
        self, replay, connected_account
    ) -> None:
        """The analysis is a question, not a change."""
        from app.services import graph as graph_service

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            graph = await graph_service.load_graph(session, org_id)

        before = len(graph.attack_paths())
        graph.choke_points()

        assert len(graph.attack_paths()) == before


class TestScenarioRisk:
    """A route through the environment, as a risk rather than a page.

    The graph could say an internet-facing host reaches customer data, and
    nothing else knew: the risk list still ranked the five underlying findings
    separately. A scenario puts the combination where the parts already are.
    """

    async def _risks(self, org_id: uuid.UUID, kind: str) -> list:
        return await fetch(
            "SELECT id, title, risk_score, status, path FROM risks "
            "WHERE organization_id = :o AND kind = :k ORDER BY risk_score DESC",
            {"o": org_id, "k": kind},
        )

    async def test_a_route_becomes_one_risk(self, replay, connected_account) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        scenarios = await self._risks(org_id, "ATTACK_PATH")
        assert scenarios, "the recorded environment contains a reachable route"

    async def test_a_scenario_outranks_the_findings_it_groups(
        self, replay, connected_account
    ) -> None:
        """The whole reason it exists. If the combination scored below its
        parts it would be buried beneath its own evidence."""
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        scenarios = await self._risks(org_id, "ATTACK_PATH")
        members = await fetch(
            "SELECT max(r.risk_score) FROM risks r "
            "JOIN risk_findings rf ON rf.risk_id = r.id "
            "WHERE r.organization_id = :o AND r.kind = 'FINDING'",
            {"o": org_id},
        )

        assert float(scenarios[0][2]) >= float(members[0][0])

    async def test_a_scenario_carries_the_route_that_made_it(
        self, replay, connected_account
    ) -> None:
        """"This is a risk" is an alarm. The hops are what somebody acts on."""
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        scenarios = await self._risks(org_id, "ATTACK_PATH")
        route = scenarios[0][4]
        assert route, "a scenario without its route cannot explain itself"
        assert all("description" in hop for hop in route)

    async def test_a_scenario_is_linked_to_its_member_findings(
        self, replay, connected_account
    ) -> None:
        """Through the junction that was built for exactly this, and has held
        one finding per risk since it was written."""
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT count(*) FROM risk_findings rf "
            "JOIN risks r ON r.id = rf.risk_id "
            "WHERE r.organization_id = :o AND r.kind = 'ATTACK_PATH'",
            {"o": org_id},
        )
        assert rows[0][0] > 0

    async def test_a_scenario_does_not_charge_the_score_twice(
        self, replay, connected_account
    ) -> None:
        """The score joins risks to findings, so a scenario with four members
        would deduct four times — and even once would charge the customer again
        for problems they have already been charged for through the parts."""
        from app.services.dashboard import build_dashboard

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            before = await build_dashboard(session, org_id)

            # Double the scenario's severity. The score must not move: it is a
            # view of findings that are already counted.
            await session.execute(
                text(
                    "UPDATE risks SET risk_score = 100, risk_level = 'CRITICAL' "
                    "WHERE organization_id = :o AND kind = 'ATTACK_PATH'"
                ),
                {"o": org_id},
            )
            await session.commit()
            after = await build_dashboard(session, org_id)

        assert before["security_score"] == after["security_score"]


    async def test_a_finding_on_a_route_still_has_its_own_risk(
        self, replay, connected_account
    ) -> None:
        """The regression a scenario introduced, and the one that crashed.

        A finding used to have at most one risk, so every lookup read the
        junction with ``scalar_one_or_none``. A finding on an attack path is
        linked twice — to its own risk and to the route — so those lookups
        began raising ``MultipleResultsFound`` on exactly the findings the graph
        had found something interesting about: the finding detail page, accepting
        a risk, and creating a remediation task.
        """
        from app.models.finding import Finding as FindingModel
        from app.services.findings import own_risk

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        # A finding that is genuinely a member of a route.
        member_ids = await fetch(
            "SELECT rf.finding_id FROM risk_findings rf "
            "JOIN risks r ON r.id = rf.risk_id "
            "WHERE r.organization_id = :o AND r.kind = 'ATTACK_PATH'",
            {"o": org_id},
        )
        assert member_ids, "the recorded environment should put findings on a route"

        async with service_session() as session:
            finding = await session.get(FindingModel, member_ids[0][0])
            links = await fetch(
                "SELECT count(*) FROM risk_findings WHERE finding_id = :f",
                {"f": finding.id},
            )
            assert links[0][0] > 1, "this finding is on a route as well as its own risk"

            risk = await own_risk(session, finding)

        assert risk is not None
        assert risk.kind.value == "FINDING", "its own risk, not the route it is on"

    async def test_the_top_risks_list_is_not_filled_by_one_scenario(
        self, replay, connected_account
    ) -> None:
        """The join fans a risk out across its findings, which was harmless
        while every risk had exactly one — and would otherwise let a scenario
        grouping four findings take four of the five places."""
        from app.services.dashboard import build_dashboard

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            summary = await build_dashboard(session, org_id)

        ids = [risk["id"] for risk in summary["top_risks"]]
        assert len(ids) == len(set(ids)), f"a risk appears more than once: {ids}"

    async def test_a_route_that_closes_is_resolved_not_deleted(
        self, replay, connected_account
    ) -> None:
        """A closed scenario is the record of a fix, exactly as a resolved
        finding is. Deleting it would erase the evidence the loop worked."""
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        assert await self._risks(org_id, "ATTACK_PATH")

        # Sever the route at its first hop, which is what the product tells the
        # customer to do: detach the managed identity from the host.
        #
        # Changed in the *environment*, not in the database. Deleting the stored
        # edge proves nothing -- the next scan re-normalizes the same capture
        # and puts it straight back, which is what this test originally did and
        # why it failed.
        severed = load_raw()
        for vm in severed["data"]["virtual_machines"]:
            vm.pop("identity", None)
        replay["payload"] = severed

        await run_scan(org_id, account_id)

        scenarios = await self._risks(org_id, "ATTACK_PATH")
        assert scenarios, "the record of the closed route survives"
        assert all(row[3] == "RESOLVED" for row in scenarios)


def _with_rdp_closed() -> dict:
    """The recorded environment with its headline problem repaired.

    The same edit the verification tests make, which is the point: a fix that
    moves the history line has to be a fix the rules actually recognise, not a
    different fixture that happens to score better.
    """
    fixed = load_raw()
    for nsg in fixed["data"]["network_security_groups"]:
        for rule in nsg["properties"]["securityRules"]:
            if rule["name"] == "AllowRDP":
                rule["properties"]["sourceAddressPrefix"] = "10.10.0.0/16"
    return fixed


class TestRiskHistory:
    """What the posture was, each time CloudGuard looked.

    "Did my risk go up?" is the question a customer asks after doing the work,
    and nothing recorded the answer — the dashboard showed an estimate that
    reconstructed a prior score by adding back every fix ever verified, which
    answers "how much better than when we started" while being labelled
    "movement since the last scan".
    """

    async def _history(self, org_id: uuid.UUID) -> list:
        return await fetch(
            "SELECT security_score, open_finding_count, attack_path_count, "
            "observed_at FROM risk_history WHERE organization_id = :o "
            "ORDER BY observed_at",
            {"o": org_id},
        )

    async def test_a_scan_records_the_posture_it_observed(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        entries = await self._history(org_id)
        assert len(entries) == 1
        assert entries[0][1] > 0, "the vulnerable fixture has open findings"

    async def test_each_scan_adds_one_reading(
        self, replay, connected_account
    ) -> None:
        """A series with two entries per scan would show movement that never
        happened."""
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        await run_scan(org_id, account_id)

        assert len(await self._history(org_id)) == 2

    async def test_a_fix_moves_the_line(self, replay, connected_account) -> None:
        """The whole point. Two readings, and the second is better than the
        first because something was actually fixed in between."""
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        replay["payload"] = _with_rdp_closed()
        await run_scan(org_id, account_id)

        entries = await self._history(org_id)
        assert len(entries) == 2
        assert entries[1][0] > entries[0][0], "the score should have improved"

    async def test_the_delta_is_measured_not_estimated(
        self, replay, connected_account
    ) -> None:
        """Against the previous reading, rather than against the sum of every
        fix ever verified."""
        from app.services.dashboard import build_dashboard

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            first = await build_dashboard(session, org_id)
        # Nothing to compare a first scan against, and saying 0 would read as
        # "no change" rather than "no comparison".
        assert first["score_delta"] is None

        replay["payload"] = _with_rdp_closed()
        await run_scan(org_id, account_id)

        async with service_session() as session:
            second = await build_dashboard(session, org_id)

        entries = await self._history(org_id)
        assert second["score_delta"] == entries[1][0] - entries[0][0]

    async def test_a_superseded_replay_records_nothing(
        self, replay, connected_account
    ) -> None:
        """It reports what today's rules would have found and changes nothing,
        so recording an entry would make the line move on a day nobody looked
        at the environment."""
        org_id, account_id = connected_account
        first = await run_scan(org_id, account_id)
        await run_scan(org_id, account_id)  # supersedes the first capture
        before = len(await self._history(org_id))

        await run_replay(org_id, account_id, first)

        assert len(await self._history(org_id)) == before

    async def test_the_series_survives_pruning_a_scan(
        self, replay, connected_account
    ) -> None:
        """Deleting an execution log must not rewrite history, exactly as it
        leaves the findings that scan raised alone."""
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
            await session.delete(scan)
            await session.commit()

        entries = await self._history(org_id)
        assert len(entries) == 1, "the reading outlives the run that took it"


class TestDeclaredContext:
    """What the customer says about a subscription, reaching the assets in it.

    Inference from tags is a guess and the customer knows the answer, so a
    declaration is applied over the top of what the capture supported. It is a
    floor rather than an override, which is the property that makes it safe to
    expose as a control: the worst a mistaken declaration can do is over-rank
    an asset, never make one look safer than it is.
    """

    async def _declare(self, org_id, account_id, **fields) -> None:
        async with service_session() as session:
            session.add(
                ContextDeclarationRecord(
                    organization_id=org_id, cloud_account_id=account_id, **fields
                )
            )
            await session.commit()

    async def _context_of(self, account_id) -> dict:
        rows = await fetch(
            "SELECT provider_resource_id, criticality, criticality_source "
            "FROM cloud_resources WHERE cloud_account_id = :a",
            {"a": account_id},
        )
        return {row[0]: (row[1], row[2]) for row in rows}

    async def test_a_declaration_reaches_every_asset_in_the_subscription(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        await self._declare(org_id, account_id, criticality=Level.CRITICAL)

        await run_scan(org_id, account_id)

        contexts = await self._context_of(account_id)
        assert contexts, "the scan discovered no assets to apply context to"
        assert all(value == "CRITICAL" for value, _ in contexts.values())
        # And it says who said so. A CRITICAL from a tag and a CRITICAL from
        # the customer multiply a finding identically, and only one of them is
        # worth arguing with.
        assert all(source == "inherited" for _, source in contexts.values())

    async def test_a_declaration_never_lowers_what_the_capture_showed(
        self, replay, connected_account
    ) -> None:
        """The safety property, checked against real assets rather than in the
        abstract: declaring the whole subscription LOW must move nothing down.
        """
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        before = await self._context_of(account_id)

        await self._declare(org_id, account_id, criticality=Level.LOW)
        await run_scan(org_id, account_id)
        after = await self._context_of(account_id)

        for provider_id, (value, _source) in before.items():
            if value != "UNKNOWN":
                assert after[provider_id][0] == value, provider_id

    async def test_a_declared_environment_replaces_the_guess(
        self, replay, connected_account
    ) -> None:
        """The case the feature exists for: a subscription whose resource names
        say sandbox and whose contents are production."""
        org_id, account_id = connected_account
        await self._declare(org_id, account_id, environment="production")

        await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT DISTINCT environment, environment_source FROM cloud_resources "
            "WHERE cloud_account_id = :a",
            {"a": account_id},
        )
        assert rows == [("production", "inherited")]

    async def test_withdrawing_a_declaration_returns_to_inference(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        await self._declare(org_id, account_id, criticality=Level.CRITICAL)
        await run_scan(org_id, account_id)

        async with service_session() as session:
            await session.execute(
                text("DELETE FROM context_declarations WHERE cloud_account_id = :a"),
                {"a": account_id},
            )
            await session.commit()
        await run_scan(org_id, account_id)

        contexts = await self._context_of(account_id)
        assert not any(source == "inherited" for _, source in contexts.values())


class TestVerification:
    """A claimed fix, and whether CloudGuard can honestly confirm it.

    The auto-resolve tests above prove a scan closes a finding it saw fixed.
    These prove the other half, which is what a customer actually experiences:
    that a claim is recorded, that an early failure is not reported as a failed
    fix, and that failing to look is never dressed up as looking and
    disagreeing.
    """

    async def _claim(self, org_id, finding_id, *, attempts: int = 0):
        async with service_session() as session:
            finding = await session.get(Finding, finding_id)
            verification = await verification_service.open_verification(
                session, organization_id=org_id, finding=finding
            )
            # Fast-forwarding the backoff rather than sleeping through it: the
            # schedule itself is covered by unit tests, and what these need is
            # the state a verification reaches after its attempts run out.
            verification.attempts = attempts
            await session.commit()
            return verification.id

    async def _verification(self, verification_id):
        async with service_session() as session:
            return await session.get(RemediationVerification, verification_id)

    async def _open_finding(self, org_id, rule_id: str = "AZ-NET-001"):
        rows = await fetch(
            "SELECT id FROM findings WHERE organization_id = :o AND rule_id = :r",
            {"o": org_id, "r": rule_id},
        )
        return rows[0][0]

    def _fix_rdp(self, replay) -> None:
        fixed = load_raw()
        for nsg in fixed["data"]["network_security_groups"]:
            for rule in nsg["properties"]["securityRules"]:
                if rule["name"] == "AllowRDP":
                    rule["properties"]["sourceAddressPrefix"] = "10.10.0.0/16"
        replay["payload"] = fixed

    async def test_a_pass_verifies_the_claim(self, replay, connected_account) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        verification_id = await self._claim(
            org_id, await self._open_finding(org_id)
        )

        self._fix_rdp(replay)
        scan_2 = await run_scan(org_id, account_id)

        verification = await self._verification(verification_id)
        assert verification.status == VerificationStatus.VERIFIED
        assert verification.verified_by_scan_id == scan_2
        assert verification.next_attempt_at is None

    async def test_an_unfixed_check_spends_an_attempt_rather_than_failing_it(
        self, replay, connected_account
    ) -> None:
        """The environment is read and still says the same thing. That is not
        yet an answer -- a change reaches a cloud's read paths in its own
        time -- so the claim stays open with another look scheduled."""
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        verification_id = await self._claim(
            org_id, await self._open_finding(org_id)
        )

        await run_scan(org_id, account_id)

        verification = await self._verification(verification_id)
        assert verification.status == VerificationStatus.PENDING
        assert verification.attempts == 1
        assert verification.last_state == RuleState.FAIL
        assert verification.next_attempt_at is not None

    async def test_the_answer_arrives_once_the_attempts_run_out(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        verification_id = await self._claim(
            org_id,
            await self._open_finding(org_id),
            attempts=len(verification_service.ATTEMPT_SCHEDULE) - 1,
        )

        await run_scan(org_id, account_id)

        verification = await self._verification(verification_id)
        assert verification.status == VerificationStatus.STILL_FAILING
        assert verification.settled_at is not None
        assert verification.next_attempt_at is None

    async def test_a_scan_that_could_not_look_says_so_rather_than_failing_the_fix(
        self, replay, connected_account
    ) -> None:
        """The distinction the whole outcome vocabulary exists for.

        A collection gap degrades the rule to UNKNOWN, and a customer who has
        done the work must not be told their fix failed because CloudGuard could
        not read the environment.
        """
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        verification_id = await self._claim(
            org_id,
            await self._open_finding(org_id),
            attempts=len(verification_service.ATTEMPT_SCHEDULE) - 1,
        )

        blind = load_raw()
        blind["errors"] = {"network": "the network API could not be read"}
        blind["gaps"] = {
            "network_security_groups": "the network API could not be read",
            "network_interfaces": "the network API could not be read",
        }
        replay["payload"] = blind
        await run_scan(org_id, account_id)

        verification = await self._verification(verification_id)
        assert verification.status == VerificationStatus.INSUFFICIENT_EVIDENCE
        assert "not a failed fix" in verification.detail

    async def test_a_claim_in_another_subscription_is_left_alone(
        self, replay, connected_tenant
    ) -> None:
        """A scan settles what it read and nothing else.

        Spending an attempt on a subscription this scan never opened would burn
        the customer's answer on a reading that never looked at their fix.
        """
        org_id, connection_id = connected_tenant
        await run_connection_scan(org_id, connection_id)

        accounts = await fetch(
            "SELECT id FROM cloud_accounts WHERE organization_id = :o ORDER BY "
            "display_name",
            {"o": org_id},
        )
        first, second = accounts[0][0], accounts[1][0]
        rows = await fetch(
            "SELECT f.id FROM findings f JOIN cloud_resources r ON r.id = f.resource_id "
            "WHERE f.organization_id = :o AND r.cloud_account_id = :a LIMIT 1",
            {"o": org_id, "a": second},
        )
        verification_id = await self._claim(org_id, rows[0][0])

        await run_scan(org_id, first)

        verification = await self._verification(verification_id)
        assert verification.attempts == 0, "a scan of another subscription observed it"
        assert verification.status == VerificationStatus.PENDING


class TestEscalationChains:
    """A route to an identity that can hand out roles.

    A different question from the attack-path template rather than a variation
    on it: not what an attacker reaches, but what they could be *given* once
    they arrive. Fixing the reachable host does not shrink that -- only the
    assignment does.
    """

    def _can_assign_roles(self, replay) -> None:
        """Turn the fixture's Contributor into a role that can grant roles.

        By removing the exclusions rather than renaming the role, because the
        exclusions are the whole distinction: Contributor and Owner both carry
        ``actions: ["*"]``, and only one of them may write role assignments.
        """
        escalating = load_raw()
        for definition in escalating["data"]["role_definitions"]:
            for permission in definition["properties"]["permissions"]:
                permission["notActions"] = []
        replay["payload"] = escalating

    async def _risks(self, org_id) -> list:
        return await fetch(
            "SELECT id, title, risk_score, status, path FROM risks "
            "WHERE organization_id = :o AND kind = 'ESCALATION'",
            {"o": org_id},
        )

    async def test_a_contributor_is_not_an_escalation_path(
        self, replay, connected_account
    ) -> None:
        """The case that decides whether this template is usable.

        Contributor holds ``*`` and is excluded from writing role assignments.
        It is on nearly every subscription in existence, and reporting it here
        would bury the real ones under a false alarm per tenant.
        """
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        assert await self._risks(org_id) == []

    async def test_a_role_that_can_assign_roles_raises_one(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        self._can_assign_roles(replay)
        await run_scan(org_id, account_id)

        risks = await self._risks(org_id)
        assert len(risks) == 1
        title, path = risks[0][1], risks[0][4]
        assert "leads to control of" in title
        # The route ends at the scope, because the scope is the size of the
        # answer -- naming what the identity could take over is what makes the
        # alarm actionable.
        assert path[-1]["relationship"] == "can_grant_roles"

    async def test_the_chain_outranks_the_findings_it_groups(
        self, replay, connected_account
    ) -> None:
        """Same floor as any scenario: it cannot rank below its own evidence."""
        org_id, account_id = connected_account
        self._can_assign_roles(replay)
        await run_scan(org_id, account_id)

        risks = await self._risks(org_id)
        worst_member = await fetch(
            "SELECT max(f.risk_score) FROM findings f "
            "JOIN risk_findings rf ON rf.finding_id = f.id "
            "WHERE rf.risk_id = :r",
            {"r": risks[0][0]},
        )
        assert float(risks[0][2]) >= float(worst_member[0][0])

    async def test_revoking_the_assignment_resolves_it_rather_than_deleting_it(
        self, replay, connected_account
    ) -> None:
        """A closed route is the record of a fix, exactly as a resolved finding
        is. Deleting it would erase the evidence that the remediation worked."""
        org_id, account_id = connected_account
        self._can_assign_roles(replay)
        await run_scan(org_id, account_id)
        assert await self._risks(org_id)

        revoked = load_raw()
        revoked["data"]["role_assignments"] = []
        replay["payload"] = revoked
        await run_scan(org_id, account_id)

        risks = await self._risks(org_id)
        assert len(risks) == 1, "the scenario was deleted rather than resolved"
        assert risks[0][3] == RiskStatus.RESOLVED

    async def test_it_does_not_displace_the_route_to_the_data(
        self, replay, connected_account
    ) -> None:
        """Both templates describe the same environment and neither replaces the
        other: one says what can be reached, the other what could be granted."""
        org_id, account_id = connected_account
        self._can_assign_roles(replay)
        await run_scan(org_id, account_id)

        kinds = await fetch(
            "SELECT DISTINCT kind FROM risks WHERE organization_id = :o",
            {"o": org_id},
        )
        assert {"ATTACK_PATH", "ESCALATION", "FINDING"} <= {k[0] for k in kinds}


class TestTemporalModel:
    """What changed, rather than only what is true now.

    Two timestamps and a snapshot blob could describe the present. They could
    not answer "what changed while I was away" or "how long did this take to
    fix", and the second is the north-star metric.
    """

    async def _changes(self, org_id) -> list:
        return await fetch(
            "SELECT c.change, c.previous_value, c.current_value, r.name "
            "FROM asset_change_events c "
            "JOIN cloud_resources r ON r.id = c.resource_id "
            "WHERE c.organization_id = :o ORDER BY c.change",
            {"o": org_id},
        )

    async def _events(self, org_id, rule_id: str = "AZ-NET-001") -> list:
        return await fetch(
            "SELECT e.event, e.previous_status, e.current_status FROM finding_events e "
            "JOIN findings f ON f.id = e.finding_id "
            "WHERE e.organization_id = :o AND f.rule_id = :r "
            "ORDER BY e.observed_at",
            {"o": org_id, "r": rule_id},
        )

    def _fix_rdp(self, replay) -> None:
        fixed = load_raw()
        for nsg in fixed["data"]["network_security_groups"]:
            for rule in nsg["properties"]["securityRules"]:
                if rule["name"] == "AllowRDP":
                    rule["properties"]["sourceAddressPrefix"] = "10.10.0.0/16"
        replay["payload"] = fixed

    async def test_a_first_scan_records_every_asset_as_appearing(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        changes = await self._changes(org_id)
        assert changes, "the first scan discovered assets and recorded none of them"
        assert {c[0] for c in changes} == {"APPEARED"}

    async def test_an_unchanged_environment_records_nothing_new(
        self, replay, connected_account
    ) -> None:
        """A feed of movement, not a log of having looked. A second scan over
        the same environment must leave the reader's week empty."""
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        first = len(await self._changes(org_id))

        await run_scan(org_id, account_id)

        assert len(await self._changes(org_id)) == first

    async def test_an_asset_that_stops_being_returned_is_recorded_once(
        self, replay, connected_account
    ) -> None:
        """A transition, not a standing condition. Derived from ``last_seen_at``
        instead, an absence would re-report itself on every scan for ever."""
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        without_storage = load_raw()
        removed = without_storage["data"]["storage_accounts"].pop(0)
        replay["payload"] = without_storage
        await run_scan(org_id, account_id)
        await run_scan(org_id, account_id)

        gone = [c for c in await self._changes(org_id) if c[0] == "DISAPPEARED"]
        assert len(gone) == 1
        assert gone[0][3] == removed["name"]

    async def test_an_asset_that_comes_back_is_the_same_asset(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        without_storage = load_raw()
        name = without_storage["data"]["storage_accounts"].pop(0)["name"]
        replay["payload"] = without_storage
        await run_scan(org_id, account_id)

        replay["payload"] = load_raw()
        await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT absent_since FROM cloud_resources WHERE organization_id = :o "
            "AND name = :n",
            {"o": org_id, "n": name},
        )
        assert len(rows) == 1, "it came back as a second asset"
        assert rows[0][0] is None, "it is still marked absent"

    async def test_a_finding_carries_its_whole_life(
        self, replay, connected_account
    ) -> None:
        """Raised, fixed, and back again. Two timestamps could not tell this
        apart from one raised and fixed once."""
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        self._fix_rdp(replay)
        await run_scan(org_id, account_id)
        replay["payload"] = load_raw()
        await run_scan(org_id, account_id)

        assert [e[0] for e in await self._events(org_id)] == [
            "DETECTED",
            "RESOLVED",
            "REOPENED",
        ]

    async def test_a_resolution_says_the_status_it_left(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        self._fix_rdp(replay)
        await run_scan(org_id, account_id)

        events = await self._events(org_id)
        resolved = next(e for e in events if e[0] == "RESOLVED")
        assert resolved[1] == "OPEN"
        assert resolved[2] == "RESOLVED"

    async def test_a_superseded_replay_writes_no_history(
        self, replay, connected_account
    ) -> None:
        """A replay of an old capture makes no observation, so it must not
        appear to have watched the environment change."""
        org_id, account_id = connected_account
        first = await run_scan(org_id, account_id)
        await run_scan(org_id, account_id)
        before = len(await self._changes(org_id)) + len(await self._events(org_id))

        await run_replay(org_id, account_id, first)

        after = len(await self._changes(org_id)) + len(await self._events(org_id))
        assert after == before


class TestContextCoverage:
    """What the score is not charging for.

    The risk formula scores UNKNOWN context just under High, so an unlabelled
    asset never sorts below a labelled one. That band used to drive the org
    security score too, which meant an estate nobody had classified was told its
    posture was worse -- CloudGuard's own blind spot spent as if it were the
    customer's risk, on the same dashboard whose coverage panel promises that
    coverage is reported beside the score and not folded into it.
    """

    async def test_the_score_charges_the_established_band_not_the_cautious_one(
        self, replay, connected_account
    ) -> None:
        from app.risk.scorer import default_scorer
        from app.services.dashboard import build_dashboard

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            dashboard = await build_dashboard(session, org_id)
        rows = await fetch(
            "SELECT risk_level, known_risk_level FROM risks "
            "WHERE organization_id = :o AND kind = 'FINDING'",
            {"o": org_id},
        )

        assert rows, "the fixture estate has findings"
        # Every risk carries both bands, and the established one is never the
        # harsher of the two.
        assert all(known is not None for _, known in rows)
        cautious = default_scorer.security_score([Level(level) for level, _ in rows])
        assert dashboard["security_score"] >= cautious

    async def test_the_guessing_is_reported_rather_than_spent(
        self, replay, connected_account
    ) -> None:
        """A number the customer can act on: label these assets and the score
        will move. Silently deducting for them instead told them nothing."""
        from app.services.dashboard import build_dashboard

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            context = (await build_dashboard(session, org_id))["coverage"]["context"]

        assert context["unclassified"] + context["classified"] > 0
        assert 0.0 <= context["ratio"] <= 1.0

    async def test_a_scenario_risk_carries_no_established_band(
        self, replay, connected_account
    ) -> None:
        """It never reaches the org score -- the findings it groups are already
        counted there -- so a second band for it would be a number nobody
        claimed."""
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT known_risk_level FROM risks "
            "WHERE organization_id = :o AND kind <> 'FINDING'",
            {"o": org_id},
        )

        assert all(known is None for (known,) in rows)


class TestEvidenceFreshness:
    """How current the picture is, which is not what coverage says.

    Coverage is the fraction of checks that reached a verdict. Freshness is how
    recently the provider was asked. A posture can be fully covered and three
    weeks out of date, and until this existed nothing said so.
    """

    async def test_a_scan_reports_what_it_read_and_when(
        self, replay, connected_account
    ) -> None:
        from app.services.dashboard import build_dashboard

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            summary = await build_dashboard(session, org_id)

        freshness = summary["evidence_freshness"]
        assert freshness["readings"] > 0
        assert freshness["oldest_at"] is not None
        # Just read, so the picture is current to within the length of a scan.
        assert freshness["stale_hours"] < 1
        assert freshness["unusable"] == 0

    async def test_a_failed_reading_is_counted_as_unusable(
        self, replay, connected_account
    ) -> None:
        """Recent and usable are two different halves of "can I trust this".

        A customer reading a freshness figure is asking whether to believe the
        picture, and a listing that failed an hour ago is fresh and worthless.
        """
        from app.services.dashboard import build_dashboard

        org_id, account_id = connected_account
        blind = load_raw()
        blind["errors"] = {"storage": "the storage API could not be read"}
        blind["gaps"] = {"storage_accounts": "the storage API could not be read"}
        replay["payload"] = blind
        await run_scan(org_id, account_id)

        async with service_session() as session:
            summary = await build_dashboard(session, org_id)

        assert summary["evidence_freshness"]["unusable"] >= 1

    async def test_the_oldest_reading_is_the_headline(
        self, replay, connected_account
    ) -> None:
        """An average would let a hundred fresh listings hide the one scope
        nobody has managed to read since Tuesday."""
        from app.services.dashboard import build_dashboard

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            await session.execute(
                text(
                    "UPDATE evidence SET collected_at = now() - interval '9 days' "
                    "WHERE organization_id = :o AND evidence_key = 'storage_accounts'"
                ),
                {"o": org_id},
            )
            await session.commit()
            summary = await build_dashboard(session, org_id)

        assert summary["evidence_freshness"]["stale_hours"] > 200


class TestFindingProvenance:
    """Which readings a finding rests on, against a real database.

    The unit tests hold the write path against fakes. These hold the two things
    a fake cannot: that the foreign keys behave as the migration declares when
    rows are actually deleted, and that a replay -- which runs a different code
    path with a different scan id -- leaves the citations standing.

    Both failures would be silent. A finding whose citations were quietly
    removed looks exactly like one raised before CloudGuard recorded them.
    """

    async def test_a_finding_cites_the_readings_its_rule_declared(
        self, replay, connected_account
    ) -> None:
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        rows = await fetch(
            "SELECT fe.evidence_key, fe.content_hash, fe.collected_at, "
            "       fe.source_scan_id, fe.evidence_id "
            "FROM finding_evidence fe "
            "JOIN findings f ON f.id = fe.finding_id "
            "WHERE f.organization_id = :o",
            {"o": org_id},
        )

        assert rows, "a scan that raised findings recorded no provenance for any"
        for key, content_hash, collected_at, source_scan_id, evidence_id in rows:
            assert key, "a citation must name the reading it cites"
            assert collected_at is not None
            assert source_scan_id == scan_id
            assert evidence_id is not None
            # The hash is NULL only where the reading produced nothing. These
            # findings came from readings that succeeded, so a NULL here means
            # the citation was written from the wrong row.
            assert content_hash is not None and len(content_hash) == 64

    async def test_every_citation_points_at_a_reading_of_the_same_key(
        self, replay, connected_account
    ) -> None:
        """The join is the claim. A citation naming ``storage_accounts`` while
        pointing at the virtual machine listing would be worse than none: it
        would answer "how do you know" with the wrong evidence, confidently."""
        org_id, _account_id = connected_account
        await run_scan(org_id, _account_id)

        mismatched = await fetch(
            "SELECT fe.evidence_key, e.evidence_key "
            "FROM finding_evidence fe "
            "JOIN evidence e ON e.id = fe.evidence_id "
            "WHERE fe.organization_id = :o AND fe.evidence_key <> e.evidence_key",
            {"o": org_id},
        )

        assert mismatched == []

    async def test_a_rescan_replaces_citations_rather_than_accumulating(
        self, replay, connected_account
    ) -> None:
        """A citation says what a finding rests on now.

        Without the delete the table grows a row per scan per key for the life
        of a finding, and the primary key would refuse the second scan outright.
        """
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        first = await fetch(
            "SELECT count(*) FROM finding_evidence WHERE organization_id = :o",
            {"o": org_id},
        )

        second_scan = await run_scan(org_id, account_id)
        after = await fetch(
            "SELECT count(*) FROM finding_evidence WHERE organization_id = :o",
            {"o": org_id},
        )
        sources = await fetch(
            "SELECT DISTINCT source_scan_id FROM finding_evidence "
            "WHERE organization_id = :o",
            {"o": org_id},
        )

        assert after[0][0] == first[0][0], "citations accumulated across scans"
        assert [row[0] for row in sources] == [second_scan], (
            "a rescan must leave its findings citing the reading it just took"
        )

    async def test_an_applied_replay_keeps_citing_the_scan_that_read(
        self, replay, connected_account
    ) -> None:
        """The regression the write path is shaped around.

        A replay collects nothing, so it owns no evidence rows. Resolving
        citations against its own id finds none -- and because they are rewritten
        each evaluation, it deletes the ones the original scan left. On the path
        whose entire purpose is confirming a fix held.
        """
        org_id, account_id = connected_account
        original_id = await run_scan(org_id, account_id)
        before = await fetch(
            "SELECT count(*) FROM finding_evidence WHERE organization_id = :o",
            {"o": org_id},
        )
        assert before[0][0] > 0, "nothing to preserve; the test proves nothing"

        replayed_id = await run_replay(org_id, account_id, original_id)

        async with service_session() as session:
            replayed = await session.get(Scan, replayed_id)
        # The precondition, asserted here rather than assumed from a
        # neighbouring test: an *advisory* replay never reaches
        # ``_persist_findings`` at all, so it would leave the citations alone
        # whether the write path resolved them correctly or not, and this test
        # would pass against the bug it exists to catch.
        assert replayed.evaluation_only is False, (
            "replaying the newest capture must be applied, or this proves nothing"
        )

        after = await fetch(
            "SELECT count(*), count(DISTINCT source_scan_id) "
            "FROM finding_evidence WHERE organization_id = :o",
            {"o": org_id},
        )
        sources = await fetch(
            "SELECT DISTINCT source_scan_id FROM finding_evidence "
            "WHERE organization_id = :o",
            {"o": org_id},
        )

        assert after[0][0] == before[0][0], "a replay removed the citations"
        assert [row[0] for row in sources] == [original_id], (
            "a replay must cite the scan that read the provider, not itself"
        )

    async def test_deleting_the_scan_leaves_the_citation_standing(
        self, replay, connected_account
    ) -> None:
        """``ON DELETE SET NULL``, and the reason the facts are copied.

        Findings outlive scans. A citation that cascaded away with its scan
        would leave the finding claiming nothing rather than claiming something
        no longer inspectable -- and the hash is what keeps it followable to the
        payload, which is stored against the blob rather than the scan.
        """
        org_id, account_id = connected_account
        scan_id = await run_scan(org_id, account_id)

        before = await fetch(
            "SELECT count(*) FROM finding_evidence WHERE organization_id = :o",
            {"o": org_id},
        )
        assert before[0][0] > 0

        async with service_session() as session:
            await session.execute(
                text("DELETE FROM scans WHERE id = :s"), {"s": scan_id}
            )
            await session.commit()

        rows = await fetch(
            "SELECT evidence_id, evidence_key, content_hash, collected_at, "
            "       source_scan_id "
            "FROM finding_evidence WHERE organization_id = :o",
            {"o": org_id},
        )

        assert len(rows) == before[0][0], "citations were deleted with the scan"
        for evidence_id, key, content_hash, collected_at, source_scan_id in rows:
            # The reading is gone with its scan; the citation is not.
            assert evidence_id is None
            assert key
            assert collected_at is not None
            # No foreign key on this column, deliberately: it is what survives.
            assert source_scan_id == scan_id
            assert content_hash is not None

    async def test_a_pruned_payload_leaves_the_citation_intact(
        self, replay, connected_account
    ) -> None:
        """The citation stays true after the bytes are gone.

        Retention prunes blobs on their own schedule, and the hash on a citation
        is not a foreign key into them for exactly that reason. What the
        endpoint then reports -- ``payload_available: false`` rather than a
        dropped row or a dead link -- is held by
        ``tests/unit/test_finding_provenance.py``; what this holds is that the
        row is still here to report on.
        """
        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        before = await fetch(
            "SELECT count(*) FROM finding_evidence WHERE organization_id = :o",
            {"o": org_id},
        )
        assert before[0][0] > 0

        async with service_session() as session:
            await session.execute(
                text("DELETE FROM evidence_blobs WHERE organization_id = :o"),
                {"o": org_id},
            )
            await session.commit()

        rows = await fetch(
            "SELECT fe.content_hash, b.content_hash "
            "FROM finding_evidence fe "
            "LEFT JOIN evidence_blobs b ON b.content_hash = fe.content_hash "
            "WHERE fe.organization_id = :o",
            {"o": org_id},
        )

        assert len(rows) == before[0][0], "citations were pruned with the payloads"
        for cited, stored in rows:
            assert cited is not None, "the hash is what keeps the citation checkable"
            assert stored is None, "the payload should be gone; the citation should not"


class TestRetention:
    """Letting go of evidence without letting go of what it proved.

    Written against a real database rather than a fake because the whole feature
    is a set of DELETEs with exceptions, and the interesting failures are the
    rows that should have survived one. A fake would return whatever it was
    told.
    """

    async def test_the_newest_capture_of_a_subscription_is_never_pruned(
        self, replay, connected_account
    ) -> None:
        """The invariant, and the one that fails silently.

        The newest capture is what an *applied* replay reads: replaying it may
        resolve findings, while every older one is advisory and may not. Pruning
        it raises nothing -- it turns "did the fix work" into an answer nobody
        can act on, on the path the product's north-star metric runs through.
        """
        from app.services import retention

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        await run_scan(org_id, account_id)

        # Every capture is now far outside any window somebody might configure.
        async with service_session() as session:
            await session.execute(
                text(
                    "UPDATE cloud_snapshots SET created_at = now() - interval "
                    "'400 days' WHERE organization_id = :o"
                ),
                {"o": org_id},
            )
            await session.commit()

        newest = await fetch(
            "SELECT id FROM cloud_snapshots WHERE organization_id = :o "
            "AND cloud_account_id IS NOT NULL "
            "ORDER BY created_at DESC, id DESC LIMIT 1",
            {"o": org_id},
        )

        async with service_session() as session:
            pruned = await retention.prune_snapshots(session, org_id, keep_days=30)
            await session.commit()

        survivors = await fetch(
            "SELECT id FROM cloud_snapshots WHERE organization_id = :o "
            "AND cloud_account_id IS NOT NULL",
            {"o": org_id},
        )

        assert pruned > 0, "nothing was pruned; the test proves nothing"
        assert [row[0] for row in survivors] == [newest[0][0]]

    async def test_the_newest_directory_capture_survives_too(
        self, replay, connected_tenant
    ) -> None:
        """A replay restores the directory beside each subscription.

        Pruned out from under one, the identity rules would read nothing while
        the subscription rules carried on -- a replay that half worked, which is
        worse than one that refused.
        """
        from app.services import retention

        org_id, connection_id = connected_tenant
        await run_connection_scan(org_id, connection_id)
        await run_connection_scan(org_id, connection_id)

        async with service_session() as session:
            await session.execute(
                text(
                    "UPDATE cloud_snapshots SET created_at = now() - interval "
                    "'400 days' WHERE organization_id = :o"
                ),
                {"o": org_id},
            )
            await session.commit()
            await retention.prune_snapshots(session, org_id, keep_days=30)
            await session.commit()

        directories = await fetch(
            "SELECT count(*) FROM cloud_snapshots WHERE organization_id = :o "
            "AND cloud_account_id IS NULL",
            {"o": org_id},
        )
        assert directories[0][0] == 1, "the directory a replay needs was pruned"

    async def test_a_capture_inside_the_window_is_kept(
        self, replay, connected_account
    ) -> None:
        """Retention is a window, not a "keep one" policy.

        Drift between two scans is a diff rather than an inference, and a
        history one capture deep cannot be diffed against anything.
        """
        from app.services import retention

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        await run_scan(org_id, account_id)

        before = await fetch(
            "SELECT count(*) FROM cloud_snapshots WHERE organization_id = :o",
            {"o": org_id},
        )

        async with service_session() as session:
            pruned = await retention.prune_snapshots(session, org_id, keep_days=30)
            await session.commit()

        after = await fetch(
            "SELECT count(*) FROM cloud_snapshots WHERE organization_id = :o",
            {"o": org_id},
        )
        assert pruned == 0
        assert after[0][0] == before[0][0]

    async def test_a_payload_still_being_re_read_is_not_pruned(
        self, replay, connected_account
    ) -> None:
        """Why the column is ``last_seen_at`` and not ``first_stored_at``.

        An estate that has not changed in six months stores one copy and touches
        it on every scan. Measuring from when it was first stored would delete
        the payload behind every current reading, which is the deduplication
        working against itself.
        """
        from app.services import retention

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        async with service_session() as session:
            # Stored long ago, seen just now: exactly the unchanged estate.
            await session.execute(
                text(
                    "UPDATE evidence_blobs SET first_stored_at = now() - interval "
                    "'400 days' WHERE organization_id = :o"
                ),
                {"o": org_id},
            )
            await session.commit()
            pruned = await retention.prune_blobs(session, org_id, keep_days=90)
            await session.commit()

        remaining = await fetch(
            "SELECT count(*) FROM evidence_blobs WHERE organization_id = :o",
            {"o": org_id},
        )
        assert pruned == 0
        assert remaining[0][0] > 0

    async def test_a_pruned_payload_leaves_its_citations_standing(
        self, replay, connected_account
    ) -> None:
        """The reason a citation copies the hash instead of holding a key.

        A finding raised last year is still answerable after its bytes are gone:
        the citation says truthfully what was read, when, and under which
        permission, and the API reports the payload as unavailable rather than
        offering a link that fails.
        """
        from app.services import retention

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)

        citations_before = await fetch(
            "SELECT count(*) FROM finding_evidence WHERE organization_id = :o",
            {"o": org_id},
        )
        assert citations_before[0][0] > 0

        async with service_session() as session:
            await session.execute(
                text(
                    "UPDATE evidence_blobs SET last_seen_at = now() - interval "
                    "'400 days' WHERE organization_id = :o"
                ),
                {"o": org_id},
            )
            await session.commit()
            pruned = await retention.prune_blobs(session, org_id, keep_days=90)
            await session.commit()

        citations_after = await fetch(
            "SELECT count(*), count(content_hash) FROM finding_evidence "
            "WHERE organization_id = :o",
            {"o": org_id},
        )

        assert pruned > 0
        assert citations_after[0][0] == citations_before[0][0]
        # And still followable in principle: the hash is what identifies the
        # bytes, whether or not they are still held.
        assert citations_after[0][1] == citations_before[0][0]

    async def test_pruning_twice_is_safe(self, replay, connected_account) -> None:
        """It runs on a timer and may overlap itself after a slow night."""
        from app.services import retention

        org_id, account_id = connected_account
        await run_scan(org_id, account_id)
        await run_scan(org_id, account_id)

        async with service_session() as session:
            await session.execute(
                text(
                    "UPDATE cloud_snapshots SET created_at = now() - interval "
                    "'400 days' WHERE organization_id = :o"
                ),
                {"o": org_id},
            )
            await session.commit()
            first = await retention.prune(
                session, org_id, snapshot_days=30, evidence_days=90
            )
            await session.commit()
            second = await retention.prune(
                session, org_id, snapshot_days=30, evidence_days=90
            )
            await session.commit()

        assert first["snapshots"] > 0
        assert second["snapshots"] == 0
