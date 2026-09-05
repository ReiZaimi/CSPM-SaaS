"""The recorded AWS environment, through the whole pipeline.

Nothing in `app/connectors/aws/` has been run against a live account, so this is
the closest thing to end-to-end proof the code has: a capture in the shape the
collector produces, normalized by the real normalizer, judged by the real rules,
with the verdicts pinned.

What it proves is that everything *after* the provider works — the regional
blocks unwrap, the per-bucket readings join, the graph resolves its capability
hop, thirty rules reach a verdict and none of them reaches UNKNOWN over evidence
that arrived. What it cannot prove is the half `docs/AWS_INTEGRATION.md` §1
covers: whether the payloads it replays are the payloads AWS actually sends.

It is also the seed's fixture (`database/seed/demo_environment.py --provider
aws`), which is deliberate. A demo assembled from fabricated findings would
prove nothing about the code that produces them, and a fixture nobody looks at
drifts from the product it is supposed to describe.
"""

import copy
import importlib.util
import json
import pathlib
from types import ModuleType

from app.connectors.aws.normalizer import AwsNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Provider, RelationshipType, ResourceType
from app.rules.base import RuleContext
from app.rules.engine import RuleEngine

FIXTURE = (
    pathlib.Path(__file__).resolve().parents[1]
    / "fixtures"
    / "aws_raw"
    / "snapshot_mixed.json"
)

# What this recorded estate is wrong about. Pinned as a set rather than a count,
# because a count tells you something changed and this tells you what.
EXPECTED_FAILURES = {
    "AWS-CMP-002",  # an instance still answers IMDSv1
    "AWS-DB-001",  # the database is publicly accessible
    "AWS-DB-002",  # and unencrypted
    "AWS-DB-003",  # and does not take minor version upgrades
    "AWS-IAM-001",  # a console user has no MFA
    "AWS-IAM-003",  # a CI key has gone unused
    "AWS-IAM-006",  # a legacy policy grants *:*
    "AWS-IAM-009",  # nobody can open a support case without root
    "AWS-LOG-008",  # nobody is alerted when root is used
    "AWS-NET-001",  # SSH is open to the internet
    "AWS-NET-004",  # a network ACL admits everything
    "AWS-NET-005",  # the default security group carries rules
    "AWS-SEC-001",  # a customer key does not rotate
    "AWS-STO-001",  # a bucket is public
    "AWS-STO-002",  # and unencrypted
    "AWS-STO-003",  # and accepts plaintext HTTP
}


def seed_module() -> ModuleType:
    """The seed script, loaded by path.

    It is deliberately not a package -- nothing in the application imports it,
    and it inserts the deployed API's path at import so it can run from a
    Railway shell. Loading it by location rather than making it importable
    keeps that true while still letting the tests hold its fix function to the
    rules it is supposed to satisfy.
    """
    path = (
        pathlib.Path(__file__).resolve().parents[4]
        / "database"
        / "seed"
        / "demo_environment.py"
    )
    spec = importlib.util.spec_from_file_location("demo_environment", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def context() -> RuleContext:
    snapshot = RawSnapshot.from_json(json.loads(FIXTURE.read_text()))
    state = AwsNormalizer().normalize(snapshot)
    relationships: dict[tuple[str, str], list[str]] = {}
    for source, kind, target in state.relationships:
        relationships.setdefault((source, kind.value), []).append(target)
    return RuleContext(
        resources=state.resources,
        relationships=relationships,
        controls=state.controls,
        collection_errors=state.collection_errors,
    )


def test_the_recording_reaches_the_verdicts_it_is_supposed_to() -> None:
    report = RuleEngine().evaluate(context())
    raised = {finding.rule.rule_id for finding in report.failures}

    assert raised == EXPECTED_FAILURES


def test_nothing_reports_unknown_over_evidence_that_arrived() -> None:
    """An UNKNOWN here is a rule reading a field the normalizer does not
    produce, which is the drift that would otherwise show up as a customer
    asking why half their checks say "not known"."""
    report = RuleEngine().evaluate(context())
    unknown = sorted(
        rule_id
        for rule_id, coverage in report.coverage.items()
        if rule_id.startswith("AWS-") and coverage.unknown_count
    )

    assert unknown == []


def test_most_of_the_estate_passes() -> None:
    """A demo where everything fails floors the security score and shows no
    green at all, which is a poor demonstration of a product whose whole point
    is telling the two apart."""
    report = RuleEngine().evaluate(context())
    passed = {
        rule_id
        for rule_id, coverage in report.coverage.items()
        if rule_id.startswith("AWS-") and coverage.passed_count
    }

    assert len(passed) > len(EXPECTED_FAILURES)


def test_no_azure_rule_touches_the_recording() -> None:
    """``STORAGE_ACCOUNT`` is neutral, so without the provider check an Azure
    rule would raise a finding carrying ``az storage account update`` as the fix
    for an S3 bucket."""
    report = RuleEngine().evaluate(context())

    assert all(f.rule.provider is Provider.AWS for f in report.failures)


def test_the_regional_blocks_unwrap_into_resources_that_know_where_they_are() -> None:
    resources = context().resources
    groups = {
        r.name: r.region
        for r in resources
        if r.resource_type is ResourceType.NETWORK_SECURITY_GROUP
    }

    assert groups == {
        "web-tier": "eu-west-1",
        "database": "eu-west-1",
        "default": "us-east-1",
    }


def test_the_capability_hop_lands_on_the_role_rather_than_the_profile() -> None:
    """An instance names its profile and the profile names the role. An edge to
    the profile stops one hop short of what the workload may actually do."""
    resolved = context()
    instance = next(
        r
        for r in resolved.resources
        if r.resource_type is ResourceType.VIRTUAL_MACHINE and r.name == "web-01"
    )
    identities = resolved.get_related(instance, RelationshipType.HAS_IDENTITY.value)

    assert [i.name for i in identities] == ["app-server"]


def test_a_repaired_estate_closes_the_findings_it_repaired() -> None:
    """The claim the product is built on: nobody clicks "resolved".

    The seed's ``--fix`` replays exactly this, which is how the auto-resolve
    path is demonstrated rather than described.
    """
    payload = json.loads(FIXTURE.read_text())
    repaired = seed_module()._apply_aws_fixes(copy.deepcopy(payload))

    state = AwsNormalizer().normalize(RawSnapshot.from_json(repaired))
    report = RuleEngine().evaluate(
        RuleContext(
            resources=state.resources,
            controls=state.controls,
            collection_errors=state.collection_errors,
        )
    )
    raised = {finding.rule.rule_id for finding in report.failures}

    # The public bucket and the open SSH rule are closed; nothing else moved.
    assert "AWS-STO-001" not in raised
    assert "AWS-NET-001" not in raised
    assert "AWS-DB-001" in raised

    passed = {
        rule_id
        for rule_id, coverage in report.coverage.items()
        if coverage.passed_count
    }
    assert {"AWS-STO-001", "AWS-NET-001"} <= passed


def test_the_bucket_fix_closes_both_ways_in() -> None:
    """The rule refuses a bucket that blocks public ACLs and still carries a
    policy granting ``*``. A fix that satisfied half of it would leave the
    finding open and make the demo look broken when it is working correctly."""
    repaired = seed_module()._apply_aws_fixes(
        copy.deepcopy(json.loads(FIXTURE.read_text()))
    )
    state = AwsNormalizer().normalize(RawSnapshot.from_json(repaired))
    bucket = next(
        r
        for r in state.resources
        if r.resource_type is ResourceType.STORAGE_ACCOUNT
        and r.name == "bk-customer-statements"
    )

    assert bucket.get("public_access_blocked") is True
    assert bucket.get("policy_is_public") is False


def test_the_capture_replays_to_the_same_verdicts() -> None:
    """A stored capture round-trips, which is what the raw snapshot exists for.

    If ``to_json`` and ``from_json`` disagreed about the regional block shape,
    every replayed AWS scan would quietly reach different conclusions from the
    scan that took the reading.
    """
    original = RawSnapshot.from_json(json.loads(FIXTURE.read_text()))
    round_tripped = RawSnapshot.from_json(original.to_json())

    first = AwsNormalizer().normalize(original)
    second = AwsNormalizer().normalize(round_tripped)

    assert [r.provider_resource_id for r in first.resources] == [
        r.provider_resource_id for r in second.resources
    ]
    assert first.controls == second.controls
