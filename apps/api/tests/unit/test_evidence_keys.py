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

from app.connectors.azure.evidence import AzureEvidence, keys_in
from app.connectors.azure.plan import AzurePlanBuilder
from app.connectors.evidence import EvidenceCategory
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


def test_every_rule_depends_on_evidence_something_collects() -> None:
    """The check that could not exist while both sides were strings."""
    produced = planned_keys()
    for rule in RULE_REGISTRY:
        for key in rule.requires_evidence:
            assert key in produced, (
                f"{rule.rule_id} declares {key.value}, which no collection task "
                "produces -- so it would never degrade if that evidence were missing"
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
