"""Seed a demo organization with a scanned environment.

Why this exists: the product loop cannot be demonstrated without a real Azure
tenant, and setting one up is a prerequisite for Phase 2 that may not be done
yet. This script runs the **real** pipeline -- real normalizer, real rules, real
risk engine -- against a recorded Azure snapshot, so what you see in the UI is
genuinely what CloudGuard computes, not fabricated rows.

It is a development tool, not part of the application. Nothing imports it, and
it refuses to run against a production environment.

    python /srv/database/seed/demo_environment.py --email you@example.com
    python /srv/database/seed/demo_environment.py --email you@example.com --fix

Run it from the API service's shell on Railway. The email must belong to
someone who has already signed in at least once, so that Supabase has created
their user record -- the demo organization is attached to that real account.

``--fix`` replays the scan with the RDP exposure and the open SQL firewall
repaired, which is how you watch a finding auto-resolve and the score move.
"""

import argparse
import asyncio
import copy
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, "/srv/apps/api")

from sqlalchemy import text

from app.connectors.azure.evidence import keys_in
from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import CloudConnector, NormalizedState, RawSnapshot
from app.connectors.evidence import EvidenceCategory
from app.core.config import settings
from app.core.db import service_session
from app.core.enums import (
    CloudAccountStatus,
    CollectionScope,
    ConnectionScope,
    ConsentStatus,
    Provider,
    ScanStatus,
)
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.scan import Scan
from app.services import orchestrator
from app.services import scanner as scanner_module
from app.services.rule_sync import sync_rules_to_database
from app.services.scanner import ScanPipeline

SNAPSHOT = Path("/srv/apps/api/tests/fixtures/azure_raw/snapshot_mixed.json")
DEMO_ORG = "Banka Kombetare (demo)"


# The recording is one file, but a scan reads two scopes: the subscription and
# the tenant directory above it. These keys belong to the second.
DIRECTORY_KEYS = frozenset(
    {"users", "directory_roles", "user_role_map", "authentication_methods"}
)


class ReplayConnector(CloudConnector):
    provider = Provider.AZURE

    def __init__(self, payload: dict, **_: object) -> None:
        self.payload = payload
        self._normalizer = AzureNormalizer()

    async def validate_connection(self):
        raise NotImplementedError

    async def collect(self, on_progress=None) -> RawSnapshot:
        return self._slice(directory=False)

    async def collect_directory(self, on_progress=None) -> RawSnapshot:
        return self._slice(directory=True)

    def _slice(self, *, directory: bool) -> RawSnapshot:
        """The recording, split the way the real connector splits its plans.

        Serving the whole thing to both would put the directory back inside the
        per-subscription read, which is the shape that produced one asset per
        subscription for every user in the tenant.
        """
        return RawSnapshot(
            provider=Provider.AZURE,
            tenant_id=self.payload["tenant_id"],
            subscription_id=(
                None if directory else self.payload["subscription_id"]
            ),
            scope=(
                CollectionScope.DIRECTORY if directory else CollectionScope.ACCOUNT
            ),
            version=self.payload["version"],
            data={
                key: copy.deepcopy(value)
                for key, value in self.payload["data"].items()
                if (key in DIRECTORY_KEYS) is directory
            },
            errors={
                category: reason
                for category, reason in self.payload["errors"].items()
                if (category == "identity") is directory
            },
            # The rules degrade per evidence key, so a recorded category error
            # has to reach the keys under it. Without this the demo would show
            # a degraded banner and rules that passed regardless -- the exact
            # contradiction the coverage ledger exists to prevent.
            gaps={
                key.value: reason
                for category, reason in self.payload["errors"].items()
                if (category == "identity") is directory
                for key in keys_in(EvidenceCategory(category))
            },
        )

    def normalize(self, snapshot: RawSnapshot) -> NormalizedState:
        return self._normalizer.normalize(snapshot)


async def drive_scan(scan_id) -> None:
    """Run a scan to completion in this process.

    A scan is normally driven by two Celery tasks passing a scan id between
    them; the seed has no broker and no worker, so it performs the same loop
    directly: ask what may run, claim it, run it, ask again. Every decision is
    still the orchestrator's and the pipeline's -- what is skipped here is only
    the queue between them.
    """
    async with service_session() as session:
        scan = await session.get(Scan, scan_id)
        await orchestrator.create_initial_steps(session, scan)
        await session.commit()

    while True:
        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
            steps = await orchestrator.sync_scan_state(session, scan)
            claimed = await orchestrator.claim(
                session, [s.id for s in orchestrator.runnable(steps)]
            )
        if not claimed:
            break
        for step_id in claimed:
            await ScanPipeline(scan_id).run_step(step_id)

    async with service_session() as session:
        scan = await session.get(Scan, scan_id)
        await orchestrator.sync_scan_state(session, scan)


def apply_fixes(payload: dict) -> dict:
    """Repair the two headline problems, as a customer would have."""
    fixed = copy.deepcopy(payload)
    for nsg in fixed["data"]["network_security_groups"]:
        for rule in nsg["properties"]["securityRules"]:
            if rule["name"] == "AllowRDP":
                rule["properties"]["sourceAddressPrefix"] = "10.10.0.0/16"
    for server in fixed["data"]["sql_servers"]:
        server["properties"]["publicNetworkAccess"] = "Disabled"
        server["_firewall_rules"] = []
    return fixed


async def resolve_user(email: str) -> uuid.UUID:
    """Find the Supabase account this demo organization should belong to.

    Supabase keeps its users in auth.users in the same database, so the owner
    connection can read it directly. Inventing a user id instead would create
    an organization that the person signing in could never see -- their real
    Supabase id would not match it.
    """
    async with service_session() as session:
        user_id = (
            await session.execute(
                text("SELECT id FROM auth.users WHERE lower(email) = lower(:e) LIMIT 1"),
                {"e": email},
            )
        ).scalar_one_or_none()

    if user_id is None:
        raise SystemExit(
            f"No Supabase user found for {email}.\n"
            "Sign in through the app once first -- Supabase creates the account "
            "when the magic link is used -- then run this again."
        )
    return user_id


async def seed(email: str, fix: bool) -> None:
    if settings.is_production:
        raise SystemExit(
            "Refusing to seed demo data into a production environment.\n"
            "Set APP_ENV=staging on this service while demoing, or connect a "
            "real Azure tenant instead."
        )

    await sync_rules_to_database()

    user_id = await resolve_user(email)
    payload = json.loads(SNAPSHOT.read_text())
    if fix:
        payload = apply_fixes(payload)

    async with service_session() as session:
        org_id = (
            await session.execute(
                text("SELECT organization_id FROM organization_members WHERE user_id = :u LIMIT 1"),
                {"u": user_id},
            )
        ).scalar_one_or_none()

        if org_id is None:
            org_id = (
                await session.execute(
                    text(
                        "INSERT INTO organizations (name, slug, industry, country) "
                        "VALUES (:n, :s, 'Financial Services', 'AL') RETURNING id"
                    ),
                    {"n": DEMO_ORG, "s": f"demo-{uuid.uuid4().hex[:8]}"},
                )
            ).scalar_one()
            await session.execute(
                text(
                    "INSERT INTO organization_members (organization_id, user_id, role) "
                    "VALUES (:o, :u, 'OWNER')"
                ),
                {"o": org_id, "u": user_id},
            )
            print(f"created organization {DEMO_ORG}")

        account_id = (
            await session.execute(
                text("SELECT id FROM cloud_accounts WHERE organization_id = :o LIMIT 1"),
                {"o": org_id},
            )
        ).scalar_one_or_none()

        if account_id is None:
            # The connection is what the tenant directory is read through, so a
            # demo account without one would show every identity check as
            # UNKNOWN -- and the MFA finding is half of what the demo is for.
            connection = CloudConnection(
                organization_id=org_id,
                provider=Provider.AZURE,
                name="Demo tenant",
                scope_type=ConnectionScope.TENANT_ROOT,
                tenant_id=payload["tenant_id"],
                consent_status=ConsentStatus.GRANTED,
                consented_at=datetime.now(UTC),
                rbac_verified_at=datetime.now(UTC),
                status=CloudAccountStatus.ACTIVE,
            )
            session.add(connection)
            await session.flush()

            account = CloudAccount(
                organization_id=org_id,
                connection_id=connection.id,
                provider=Provider.AZURE,
                account_name="Production Subscription (demo)",
                tenant_id=payload["tenant_id"],
                subscription_id=payload["subscription_id"],
                consent_status=ConsentStatus.GRANTED,
                consented_at=datetime.now(UTC),
                rbac_verified_at=datetime.now(UTC),
                status=CloudAccountStatus.ACTIVE,
                status_detail="Demo connection seeded from a recorded snapshot.",
            )
            session.add(account)
            await session.flush()
            account_id = account.id
            print("created demo cloud account")

        scan = Scan(
            organization_id=org_id,
            cloud_account_id=account_id,
            status=ScanStatus.QUEUED,
        )
        session.add(scan)
        await session.commit()
        scan_id = scan.id

    # Point the pipeline at the recorded snapshot for this run only.
    original = scanner_module.get_connector
    scanner_module.get_connector = lambda _provider, **kw: ReplayConnector(payload, **kw)
    try:
        await drive_scan(scan_id)
    finally:
        scanner_module.get_connector = original

    async with service_session() as session:
        row = (
            await session.execute(
                text(
                    "SELECT status, resource_count, rule_count, finding_count "
                    "FROM scans WHERE id = :s"
                ),
                {"s": scan_id},
            )
        ).one()
        resolved = (
            await session.execute(
                text(
                    "SELECT count(*) FROM findings WHERE organization_id = :o "
                    "AND status = 'RESOLVED'"
                ),
                {"o": org_id},
            )
        ).scalar_one()

    print(
        f"scan {row[0]}: {row[1]} resources, {row[2]} rules, "
        f"{row[3]} open findings, {resolved} verified fixed"
    )
    print(f"\nOpen {settings.app_url} and sign in as {email}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--email",
        required=True,
        help="email of an existing Supabase user to attach the demo organization to",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="replay with the RDP and SQL exposures repaired, to watch findings auto-resolve",
    )
    args = parser.parse_args()
    asyncio.run(seed(args.email, args.fix))
