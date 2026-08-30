"""What a route is worth, given what is already known about its parts.

A finding is scored for the asset it was made on. A scenario is several of them
seen as one thing, and it has to rank above any of its parts without being able
to invent the reason — the members are the evidence, and the scenario only adds
the observation that they join up.
"""

from app.core.enums import Level
from app.risk.scorer import default_scorer


def score(members: list[float], hops: int = 2, **kw) -> float:
    return default_scorer.scenario_score(
        members,
        hops=hops,
        entry_exposure=kw.get("entry_exposure", Level.CRITICAL),
        target_sensitivity=kw.get("target_sensitivity", Level.HIGH),
    ).score


def test_a_scenario_never_ranks_below_its_worst_member() -> None:
    """The floor, and the reason there is one.

    A formula that could rank a route below the critical misconfiguration
    inside it would bury the route beneath its own evidence.
    """
    assert score([84.0]) >= 84.0
    assert score([84.0, 41.0, 66.0]) >= 84.0


def test_the_combination_adds_something() -> None:
    """Otherwise a scenario is a relabelled finding and the whole exercise is
    presentation."""
    assert score([60.0]) > 60.0


def test_a_shorter_route_is_worth_more_than_a_long_one() -> None:
    """Every hop is another thing that has to hold for the route to be real,
    and a short one is both likelier and cheaper to describe."""
    assert score([60.0], hops=2) > score([60.0], hops=4)


def test_a_long_chain_stops_adding_anything() -> None:
    """Converging on zero rather than on a small number: at some length a route
    is a containment chain being walked for its own sake, and it should stop
    contributing rather than keep trickling."""
    assert score([60.0], hops=9) == 60.0


def test_the_amplifier_is_bounded() -> None:
    """An unbounded structural term would let a long chain of ordinary facts
    outrank a genuinely critical finding, which is how a score stops meaning
    anything."""
    from app.risk.config import DEFAULT_RISK_CONFIG

    for hops in range(1, 8):
        added = score([50.0], hops=hops) - 50.0
        assert 0 <= added <= DEFAULT_RISK_CONFIG.max_scenario_amplifier


def test_reaching_something_unremarkable_adds_less() -> None:
    """The ends decide whether joining them is worth saying at all."""
    high = score([60.0], target_sensitivity=Level.CRITICAL)
    low = score([60.0], target_sensitivity=Level.LOW)
    assert high > low


def test_the_score_is_capped_at_one_hundred() -> None:
    assert score([98.0], hops=1) <= 100.0


def test_the_breakdown_names_every_term() -> None:
    """"Why is this 91?" has to be answerable without rerunning anything — and
    the floor has to be visibly the members' rather than something the scorer
    decided."""
    scored = default_scorer.scenario_score(
        [84.0], hops=2, entry_exposure=Level.CRITICAL, target_sensitivity=Level.HIGH
    )

    assert scored.breakdown["worst_member"] == 84.0
    assert set(scored.breakdown) == {
        "worst_member",
        "amplifier",
        "hops",
        "shortness",
        "ends",
        "amplifier_cap",
        "uncapped",
        "total",
    }
    assert (
        scored.breakdown["worst_member"] + scored.breakdown["amplifier"]
        == scored.breakdown["uncapped"]
    )


def test_the_breakdown_explains_the_ceiling() -> None:
    """A scenario that came to 101 and shows 100 would leave the terms visibly
    not adding up, which is worse than not showing them at all."""
    scored = default_scorer.scenario_score(
        [98.0], hops=1, entry_exposure=Level.CRITICAL, target_sensitivity=Level.CRITICAL
    )

    assert scored.score == 100.0
    assert scored.breakdown["uncapped"] > 100.0


def test_a_scenario_with_no_members_scores_from_nothing() -> None:
    """Guarded here as well as at the call site.

    The pipeline does not create a scenario without members — a route with
    nothing misconfigured on it is architecture, not a mistake — and if that
    guard ever slipped, this would produce a small honest number rather than a
    severity nobody assigned.
    """
    assert score([]) <= default_scorer.config.max_scenario_amplifier
