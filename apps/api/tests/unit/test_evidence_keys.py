"""What a rule needs and what a task produces must be the same thing.

Both halves used to be bare strings. A rule declaring evidence no task produced
did not fail, raise, or warn -- it simply never degraded, which is precisely the
failure the degradation mechanism exists to prevent. There was one in the tree:
``has_collection_error("identity", "mfa")``, where nothing has ever produced
``mfa``.

Typed keys make most of that a type error. These pin the parts the type checker
cannot see: that every key a rule names is actually collected, that every key
has a category, and that the plan and the enum agree in both directions.
"""

import httpx

from app.connectors.aws.evidence import AwsEvidence
from app.connectors.aws.plan import ACTION_KEYS
from app.connectors.azure.evidence import AzureEvidence, keys_in
from app.connectors.azure.plan import AzurePlanBuilder
from app.connectors.evidence import EvidenceCategory, EvidenceKey
from app.core.enums import Provider, ResourceType
from app.rules.registry import RULE_REGISTRY


class FakeTokens:
    def arm_token(self) -> str:
        return "arm"

    def graph_token(self) -> str:
        return "graph"


def planned_keys() -> set[AzureEvidence]:
    """Every key both Azure plans produce.

    ``build_*`` only assembles closures, so this touches no network.
    """
    builder = AzurePlanBuilder(
        tokens=FakeTokens(),
        subscription_id="sub-1",
        http_client=httpx.AsyncClient(),
    )
    directory = AzurePlanBuilder(
        tokens=FakeTokens(), subscription_id=None, http_client=httpx.AsyncClient()
    )
    return {t.key for t in builder.build_account_plan()} | {
        t.key for t in directory.build_directory_plan()
    }


def collected_keys(provider: Provider) -> set[EvidenceKey]:
    """Every key that provider's plans produce.

    Azure's is read off the plans directly, which touches no network because
    ``build_*`` only assembles closures. AWS's plan is async and its *shape*
    depends on a live region listing, so it is read off ``ACTION_KEYS`` instead
    -- which ``test_aws_evidence`` pins against the enum, and ``test_aws_plan``
    pins against the tasks. Two hops rather than one, each of them checked.
    """
    if provider is Provider.AZURE:
        return set(planned_keys())
    return {key for keys in ACTION_KEYS.values() for key in keys}


def test_every_rule_depends_on_evidence_something_collects() -> None:
    """The check that could not exist while both sides were strings.

    Per provider, because the keys are. An AWS rule declaring an Azure key would
    be checked against Azure's plan and pass, which is exactly the drift a
    second provider makes possible.
    """
    for rule in RULE_REGISTRY:
        produced = collected_keys(rule.provider)
        for key in rule.requires_evidence:
            assert key in produced, (
                f"{rule.rule_id} declares {key.value}, which no "
                f"{rule.provider.value} collection task produces -- so it would "
                "never degrade if that evidence were missing"
            )


def test_a_rule_declares_its_own_provider_evidence() -> None:
    """A key from the wrong cloud degrades on something that never runs.

    It would also never appear in that scan's gaps, so the rule would evaluate
    against whatever the other provider's capture happened to hold.
    """
    expected = {Provider.AZURE: AzureEvidence, Provider.AWS: AwsEvidence}
    for rule in RULE_REGISTRY:
        for key in rule.requires_evidence:
            assert isinstance(key, expected[rule.provider]), (
                f"{rule.rule_id} is a {rule.provider.value} rule declaring "
                f"{type(key).__name__}"
            )


def test_every_rule_declares_the_evidence_it_reads() -> None:
    """A rule with no declared evidence cannot degrade at all.

    Which means it would return PASS over an environment CloudGuard failed to
    read -- the exact overclaim the four-state algebra exists to prevent.
    """
    for rule in RULE_REGISTRY:
        assert rule.requires_evidence, (
            f"{rule.rule_id} declares no evidence, so nothing can degrade it"
        )


def test_every_collected_key_is_a_declared_member() -> None:
    """The other direction: a task producing a key outside the enum would be
    invisible to every rule that might have wanted it."""
    for key in planned_keys():
        assert isinstance(key, AzureEvidence)
    for key in collected_keys(Provider.AWS):
        assert isinstance(key, AwsEvidence)


def test_every_key_maps_to_a_category() -> None:
    """A task derives its category from its key, so an unmapped key would fail
    inside a running scan rather than at import."""
    for key in AzureEvidence:
        assert isinstance(key.category, EvidenceCategory)


def test_categories_partition_the_keys() -> None:
    """Every key belongs to exactly one category, and none is orphaned.

    ``keys_in`` is how a category-level fact -- a stale role granting no
    permission for a whole category -- reaches the rules that lost their verdict
    one key at a time.
    """
    covered: set[AzureEvidence] = set()
    for category in EvidenceCategory:
        members = keys_in(category)
        assert not (covered & members), "a key belongs to two categories"
        covered |= members
    assert covered == set(AzureEvidence)


def test_the_permission_map_covers_every_collected_category() -> None:
    """``rbac.py`` groups permissions by category, and the role-drift
    explanation is keyed on the same values. A category the plan collects but
    the permission map does not name would degrade with no explanation."""
    from app.connectors.azure.rbac import COLLECTION_ACTIONS

    collected = {key.category for key in planned_keys()}
    # Identity is Graph, granted by admin consent rather than by the ARM role,
    # so it is deliberately absent from the ARM permission map.
    ungranted = collected - set(COLLECTION_ACTIONS) - {EvidenceCategory.IDENTITY}
    assert not ungranted, (
        f"categories collected over ARM with no declared permission: {ungranted}"
    )


def test_the_mfa_rule_depends_on_the_evidence_it_actually_reads() -> None:
    """The concrete bug the typing removed.

    AZ-ID-001 asked about ``identity`` and ``mfa``. The second matched nothing,
    so half the call was decoration; the first was a category, so the rule also
    degraded over directory listings it never touched. It now names the three
    tasks whose output it reads, and every one of them exists.
    """
    from app.rules.azure.identity.mfa import AzureMfaRule

    assert set(AzureMfaRule.requires_evidence) == {
        AzureEvidence.USERS,
        AzureEvidence.DIRECTORY_ROLES,
        AzureEvidence.USER_ROLE_MAP,
    }


def test_every_collected_key_is_wanted_by_a_rule_or_declared_baseline() -> None:
    """Nothing is collected because it always has been.

    A plan is derived from the rule set plus the connector's baseline, so a key
    in neither would simply stop being gathered. Failing here is the cheap
    version of that: either some rule reads it and should say so, or the product
    needs it and ``baseline_evidence`` should say so.
    """
    from app.connectors.azure.connector import AzureConnector

    wanted = {key for rule in RULE_REGISTRY for key in rule.requires_evidence}
    unexplained = planned_keys() - wanted - AzureConnector.baseline_evidence()
    assert not unexplained, (
        f"collected but nothing declares a need for it: "
        f"{sorted(k.value for k in unexplained)}"
    )


def test_the_baseline_is_evidence_the_plans_actually_produce() -> None:
    """The other direction: a baseline key no task produces asks for nothing."""
    from app.connectors.azure.connector import AzureConnector

    assert AzureConnector.baseline_evidence() <= planned_keys()


def test_no_rule_reads_evidence_that_may_be_carried_forward() -> None:
    """The line that keeps "verified fixed" true.

    A reuse window says a stale reading of this key cannot change a verdict.
    The moment a rule reads that key, it can: a customer fixes something, asks
    CloudGuard to check, and is answered from the environment as it stood before
    the fix. Granting a window is therefore allowed only for evidence no rule
    depends on, and this is where that is enforced rather than remembered.
    """
    judged = {key for rule in RULE_REGISTRY for key in rule.requires_evidence}
    reusable = {key for key in AzureEvidence if key.reuse_window is not None}
    overlap = judged & reusable
    assert not overlap, (
        "these keys may be carried forward and are also read by a rule, so a "
        f"verdict could be reached from stale evidence: {sorted(k.value for k in overlap)}"
    )


# ------------------------------------- a reading no verdict rests on
def test_no_rule_degrades_on_the_inventory() -> None:
    """The inventory is collected for the product, not for a verdict.

    Resource Graph answers "what is in this subscription" across every resource
    type, including the many CloudGuard has no rule for. Every rule reads its
    own service listing instead -- storage from the storage listing, SQL from
    the SQL listing -- so a failed inventory query costs no check its answer.

    Asserted rather than assumed, because the two keys that bit recently bit in
    exactly this way: ``sql_servers`` covered three calls, so a refusal of one
    took the verdict of rules reading the others. A key nothing declares cannot
    do that, and this is what keeps it so -- the day a rule reads the inventory,
    it declares it here and this test says so.
    """
    declaring = [
        rule.rule_id
        for rule in RULE_REGISTRY
        if AzureEvidence.RESOURCES in rule.requires_evidence
    ]
    assert declaring == [], (
        "these rules depend on the inventory, so a failed Resource Graph query "
        f"now costs them their verdict: {declaring}"
    )


def test_the_inventory_payload_is_read_and_no_rule_judges_it() -> None:
    """Both halves, and they are not in tension.

    The inventory used to be collected on every scan, stored in every snapshot,
    and read by nothing -- justified by a comment claiming the customer's asset
    list was made of it, which it was not. It is read now: the resources no
    service listing produced become assets carrying ``ResourceType.UNKNOWN``,
    counted and listed as unchecked.

    No rule declares it and none ever should. ``UNKNOWN`` appears in no rule's
    ``applies_to``, so nothing judges these and none of them can become a PASS
    nobody earned -- the point is that they are visibly *not* checked, which is
    a fact about CloudGuard rather than about the customer.
    """
    from pathlib import Path

    import app.connectors.azure.normalizer as normalizer

    source = Path(normalizer.__file__).read_text()
    assert 'data.get("resources", [])' in source, (
        "nothing reads the inventory, so it is a query per subscription per "
        "scan and a stored blob for a capability that does not exist"
    )

    judging = [
        rule.rule_id
        for rule in RULE_REGISTRY
        if ResourceType.UNKNOWN in rule.applies_to
    ]
    assert judging == [], (
        "these rules would judge a resource CloudGuard holds no configuration "
        f"for, so their verdict rests on nothing: {judging}"
    )


def test_the_inventory_is_still_collected_though_no_rule_reads_it() -> None:
    """And it must stay declared as baseline while it is.

    A plan is derived from the rule set plus the baseline. The moment nothing
    names the inventory it stops being collected -- silently, since no check
    would fail. This is the pair to the test above: one says no verdict rests
    on it, the other says it is gathered anyway and on purpose.
    """
    from app.connectors.azure.connector import AzureConnector

    assert AzureEvidence.RESOURCES in AzureConnector.baseline_evidence()
    assert AzureEvidence.RESOURCES in planned_keys()

