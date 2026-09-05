"""Seed a demo organization with a scanned environment.

Why this exists: the product loop cannot be demonstrated without a real cloud
account, and setting one up may not be done yet. This script runs the **real**
pipeline -- real normalizer, real rules, real risk engine -- against a recorded
snapshot, so what you see in the UI is genuinely what CloudGuard computes, not
fabricated rows.

It does more than that for AWS. Nothing in ``app/connectors/aws/`` has ever been
run against a live account (``docs/AWS_INTEGRATION.md`` §1), so this is the only
way to watch that half of the product work end to end: the recording exercises
the normalizer, thirty rules, the risk engine and the findings lifecycle without
touching AWS. What it cannot prove is the part the checklist covers -- whether
the payloads it replays are the payloads AWS actually sends.

It is a development tool, not part of the application. Nothing imports it, and
it refuses to run against a production environment.

    python /srv/database/seed/demo_environment.py --email you@example.com
    python /srv/database/seed/demo_environment.py --email you@example.com --provider aws
    python /srv/database/seed/demo_environment.py --email you@example.com --fix

Run it from the API service's shell on Railway. The email must belong to
someone who has already signed in at least once, so that Supabase has created
their user record -- the demo organization is attached to that real account.

``--fix`` replays the scan with two headline problems repaired, which is how you
watch a finding auto-resolve and the score move.
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

from app.connectors.aws.normalizer import AwsNormalizer
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

SNAPSHOTS = {
    Provider.AZURE: Path("/srv/apps/api/tests/fixtures/azure_raw/snapshot_mixed.json"),
    Provider.AWS: Path("/srv/apps/api/tests/fixtures/aws_raw/snapshot_mixed.json"),
}
DEMO_ORG = "Banka Kombetare (demo)"

NORMALIZERS = {Provider.AZURE: AzureNormalizer, Provider.AWS: AwsNormalizer}


# The recording is one file, but a scan reads two scopes: the account and the
# trust boundary above it. These keys belong to the second.
#
# Azure's directory is where its users live, so the split matters: served to
# both scopes, one administrator without MFA becomes one finding per
# subscription. AWS keeps identity *in* each account, so its boundary reading is
# the account list and nothing else -- which is why its set is one key.
DIRECTORY_KEYS = {
    Provider.AZURE: frozenset(
        {"users", "directory_roles", "user_role_map", "authentication_methods"}
    ),
    Provider.AWS: frozenset({"organization_accounts"}),
}


class ReplayConnector(CloudConnector):
    """Serves a recording where a real connector would call a cloud.

    The provider comes from the recording rather than from the class, so the
    same replay drives either pipeline -- and the normalizer is the real one for
    that cloud, which is the whole point: a demo assembled from fabricated
    findings would prove nothing about the code that produces them.
    """

    def __init__(self, payload: dict, **_: object) -> None:
        self.payload = payload
        self.provider = Provider(payload["provider"])
        self._normalizer = NORMALIZERS[self.provider]()
        self._directory_keys = DIRECTORY_KEYS[self.provider]

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
            provider=self.provider,
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
                if (key in self._directory_keys) is directory
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
                for key in self._keys_in(EvidenceCategory(category))
            },
        )

    def _keys_in(self, category: EvidenceCategory):
        """Which evidence keys a recorded category error should degrade.

        Asked of the provider rather than of Azure's enum. A recorded error is
        stored per category and the rules degrade per key, so getting this wrong
        would show a degraded banner over rules that passed regardless -- the
        contradiction the coverage ledger exists to prevent.
        """
        if self.provider is Provider.AZURE:
            return keys_in(category)
        from app.connectors.aws.evidence import keys_in as aws_keys_in

        return aws_keys_in(category)

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
        for step_id, _kind in claimed:
            await ScanPipeline(scan_id).run_step(step_id)

    async with service_session() as session:
        scan = await session.get(Scan, scan_id)
        await orchestrator.sync_scan_state(session, scan)


def apply_fixes(payload: dict) -> dict:
    """Repair the headline problems, as a customer would have.

    Two per cloud, chosen so the replay demonstrates the thing the product is
    actually for: nobody clicks "resolved". The next scan reads the repaired
    state, the rules pass, and the findings close themselves.
    """
    fixed = copy.deepcopy(payload)
    if Provider(fixed["provider"]) is Provider.AWS:
        return _apply_aws_fixes(fixed)

    for nsg in fixed["data"]["network_security_groups"]:
        for rule in nsg["properties"]["securityRules"]:
            if rule["name"] == "AllowRDP":
                rule["properties"]["sourceAddressPrefix"] = "10.10.0.0/16"
    for server in fixed["data"]["sql_servers"]:
        server["properties"]["publicNetworkAccess"] = "Disabled"
        server["_firewall_rules"] = []
    return fixed


def _apply_aws_fixes(fixed: dict) -> dict:
    """Close the public bucket and the open SSH rule.

    The bucket needs both halves -- the access block *and* the policy -- because
    they are two independent ways in and blocking one leaves the other open.
    That is the rule's own position, and a fix that satisfied only half of it
    would leave the finding open and make the demo look broken when it is
    working correctly.
    """
    data = fixed["data"]
    for row in data["s3_public_access_block"]:
        if row["Bucket"] == "bk-customer-statements":
            row["Configuration"] = {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
    for row in data["s3_bucket_policy_status"]:
        if row["Bucket"] == "bk-customer-statements":
            row["Configuration"] = {"PolicyStatus": {"IsPublic": False}}

    for block in data["security_groups"]:
        for group in block["items"]:
            if group["GroupId"] != "sg-0web":
                continue
            group["IpPermissions"] = [
                rule
                for rule in group["IpPermissions"]
                if not (rule.get("FromPort") == 22 and rule.get("ToPort") == 22)
            ]
    return fixed


def grant_version(provider: Provider) -> str:
    """What a connection deployed today would be stamped with.

    Hard-coding one would leave the demo reporting "redeploy the role" against
    a version that only exists in a recording -- a prompt with nothing behind
    it, on the screen whose job is to say whether access is current.
    """
    from app.connectors.registry import get_onboarding

    return get_onboarding(provider).grant_version()


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


async def seed(email: str, fix: bool, provider: Provider) -> None:
    if settings.is_production:
        raise SystemExit(
            "Refusing to seed demo data into a production environment.\n"
            "Set APP_ENV=staging on this service while demoing, or connect a "
            "real cloud account instead."
        )

    await sync_rules_to_database()

    user_id = await resolve_user(email)
    payload = json.loads(SNAPSHOTS[provider].read_text())
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
            # The connection is what the trust boundary is read through, so a
            # demo account without one would show every identity check as
            # UNKNOWN -- and the MFA finding is half of what the demo is for.
            #
            # Both grants are stamped as proven. That is honest for a replay:
            # nothing is being called, and leaving them unset would park the
            # connection in a setup step the demo is not about.
            aws = provider is Provider.AWS
            connection = CloudConnection(
                organization_id=org_id,
                provider=provider,
                name="Demo organization" if aws else "Demo tenant",
                scope_type=(
                    ConnectionScope.ORGANIZATION if aws else ConnectionScope.TENANT_ROOT
                ),
                scope_id=payload["subscription_id"] if aws else None,
                tenant_id=payload["tenant_id"],
                role_version=grant_version(provider),
                provider_ref=(
                    {
                        "role_arn": (
                            f"arn:aws:iam::{payload['subscription_id']}"
                            ":role/CloudGuardScannerRole"
                        ),
                        "external_id": "cg-demo-recording-not-a-credential",
                    }
                    if aws
                    else {}
                ),
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
                provider=provider,
                account_name=(
                    "Production Account (demo)" if aws else "Production Subscription (demo)"
                ),
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
        "--provider",
        default=Provider.AZURE.value,
        choices=[Provider.AZURE.value, Provider.AWS.value],
        help="which recorded environment to seed",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="replay with two headline exposures repaired, to watch findings auto-resolve",
    )
    args = parser.parse_args()
    asyncio.run(seed(args.email, args.fix, Provider(args.provider)))
