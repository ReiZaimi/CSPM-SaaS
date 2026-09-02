"""Risk formula (RISK_ENGINE.md section 1) and org security score (section 3)."""

from itertools import pairwise

import pytest

from app.core.enums import Level, Priority, Severity
from app.risk.config import DEFAULT_RISK_CONFIG, RiskEngineConfig, RiskWeights
from app.risk.scorer import RiskInputs, RiskScorer

scorer = RiskScorer()


def test_weights_sum_to_one() -> None:
    assert DEFAULT_RISK_CONFIG.weights.total() == pytest.approx(1.0)


def test_invalid_weights_are_rejected() -> None:
    """A misconfigured weight set must fail loudly, not silently rescale."""
    with pytest.raises(ValueError, match="must sum to 1.0"):
        RiskEngineConfig(weights=RiskWeights(severity=0.9))


def test_worst_case_scores_100() -> None:
    result = scorer.score(
        RiskInputs(
            severity=Severity.CRITICAL,
            asset_criticality=Level.CRITICAL,
            data_sensitivity=Level.CRITICAL,
            internet_exposure=Level.CRITICAL,
            exploitability=5,
        )
    )
    assert result.score == 100.0
    assert result.level == Level.CRITICAL


def test_best_case_scores_20() -> None:
    """All-LOW is 1.0 on every 0-5 component, so 1 * 20 = 20, not 0."""
    result = scorer.score(
        RiskInputs(
            severity=Severity.LOW,
            asset_criticality=Level.LOW,
            data_sensitivity=Level.LOW,
            internet_exposure=Level.LOW,
            exploitability=1,
        )
    )
    assert result.score == 20.0
    assert result.level == Level.LOW


def test_low_severity_on_low_value_asset_is_low_risk() -> None:
    result = scorer.score(
        RiskInputs(
            severity=Severity.LOW,
            asset_criticality=Level.LOW,
            data_sensitivity=Level.LOW,
            internet_exposure=Level.LOW,
            exploitability=0,
        )
    )
    assert result.level == Level.LOW


def test_critical_finding_on_exposed_critical_asset_is_critical_band() -> None:
    result = scorer.score(
        RiskInputs(
            severity=Severity.CRITICAL,
            asset_criticality=Level.CRITICAL,
            data_sensitivity=Level.CRITICAL,
            internet_exposure=Level.CRITICAL,
            exploitability=5,
        )
    )
    assert result.level == Level.CRITICAL
    assert result.score >= 75


def test_same_finding_scores_lower_on_a_dev_box() -> None:
    """The whole reason Finding and Risk are separate entities."""
    shared = {"severity": Severity.CRITICAL, "exploitability": 5}
    prod = scorer.score(
        RiskInputs(
            asset_criticality=Level.CRITICAL,
            data_sensitivity=Level.CRITICAL,
            internet_exposure=Level.CRITICAL,
            **shared,
        )
    )
    dev = scorer.score(
        RiskInputs(
            asset_criticality=Level.LOW,
            data_sensitivity=Level.LOW,
            internet_exposure=Level.LOW,
            **shared,
        )
    )
    assert prod.score > dev.score
    assert prod.level == Level.CRITICAL
    assert dev.level in {Level.MEDIUM, Level.HIGH}


def test_business_impact_is_computed_not_supplied() -> None:
    result = scorer.score(
        RiskInputs(
            severity=Severity.HIGH,
            asset_criticality=Level.CRITICAL,   # 5.0
            data_sensitivity=Level.LOW,          # 1.0
            internet_exposure=Level.MEDIUM,
            exploitability=3,
        )
    )
    assert result.business_impact == pytest.approx(3.0)


def test_unknown_scores_just_below_high() -> None:
    """UNKNOWN must never read as low risk (RISK_ENGINE.md section 1)."""
    cfg = DEFAULT_RISK_CONFIG
    assert cfg.level_scores[Level.MEDIUM] < cfg.level_scores[Level.UNKNOWN]
    assert cfg.level_scores[Level.UNKNOWN] < cfg.level_scores[Level.HIGH]


def test_unknown_context_outscores_low_context() -> None:
    shared = {"severity": Severity.HIGH, "exploitability": 3}
    unknown = scorer.score(
        RiskInputs(
            asset_criticality=Level.UNKNOWN,
            data_sensitivity=Level.UNKNOWN,
            internet_exposure=Level.UNKNOWN,
            **shared,
        )
    )
    low = scorer.score(
        RiskInputs(
            asset_criticality=Level.LOW,
            data_sensitivity=Level.LOW,
            internet_exposure=Level.LOW,
            **shared,
        )
    )
    assert unknown.score > low.score


def test_exploitability_is_clamped() -> None:
    """A typo in a rule's static tag must not blow past the 0-100 range."""
    result = scorer.score(
        RiskInputs(
            severity=Severity.CRITICAL,
            asset_criticality=Level.CRITICAL,
            data_sensitivity=Level.CRITICAL,
            internet_exposure=Level.CRITICAL,
            exploitability=99,
        )
    )
    assert result.score == 100.0


def test_breakdown_contributions_reconstruct_the_total() -> None:
    """The UI shows this breakdown as the answer to 'why is this 78?'."""
    result = scorer.score(
        RiskInputs(
            severity=Severity.HIGH,
            asset_criticality=Level.MEDIUM,
            data_sensitivity=Level.HIGH,
            internet_exposure=Level.CRITICAL,
            exploitability=4,
        )
    )
    total = sum(c["contribution"] for c in result.breakdown["components"].values())
    assert total == pytest.approx(result.score, abs=0.05)


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0, Level.LOW), (24, Level.LOW), (25, Level.MEDIUM), (49, Level.MEDIUM),
     (50, Level.HIGH), (74, Level.HIGH), (75, Level.CRITICAL), (100, Level.CRITICAL)],
)
def test_band_boundaries(score: float, expected: Level) -> None:
    assert scorer.band(score) == expected


class TestSecurityScore:
    def test_clean_environment_scores_100(self) -> None:
        assert scorer.security_score([]) == 100

    def test_two_criticals_drop_score_to_60(self) -> None:
        """Stated explicitly in RISK_ENGINE.md section 3."""
        assert scorer.security_score([Level.CRITICAL, Level.CRITICAL]) == 60

    def test_mixed_findings(self) -> None:
        # 20 + 8 + 8 + 3 + 1 = 40 deducted, which is the anchor's deduction, so
        # this lands on the anchor's score.
        levels = [Level.CRITICAL, Level.HIGH, Level.HIGH, Level.MEDIUM, Level.LOW]
        assert scorer.security_score(levels) == 60

    def test_every_critical_fixed_moves_the_number(self) -> None:
        """The regression this curve exists for.

        Subtracting from 100 and clamping made the score stop moving exactly
        where a customer needs it to: five open Criticals scored 0, twenty
        scored 0, and so did the same estate after seven were fixed. Months of
        remediation showed a flat line on the product whose north-star metric is
        verified risk reduction.
        """
        scores = [scorer.security_score([Level.CRITICAL] * n) for n in range(0, 16)]

        assert scores[0] == 100
        assert all(
            later < earlier for earlier, later in pairwise(scores)
        ), scores

    def test_a_badly_broken_estate_still_scores_badly(self) -> None:
        """Not flat is not the same as forgiving. Five open Criticals is a red
        number, not a mid-range one."""
        assert scorer.security_score([Level.CRITICAL] * 5) < 40

    def test_zero_is_where_a_catastrophe_ends_up_not_where_bad_starts(self) -> None:
        assert scorer.security_score([Level.CRITICAL] * 8) > 0
        assert scorer.security_score([Level.CRITICAL] * 40) == 0

    def test_the_anchor_holds_when_the_deductions_are_retuned(self) -> None:
        """The calibration is what is configured, not a decay rate. The doc's
        sentence -- two open Criticals leave 60 -- has to stay true after
        somebody tunes what a Critical costs, or the number in the doc and the
        number on the dashboard part company silently.

        And because the curve is fitted to that anchor, the *size* of the
        deductions is absorbed by it: scaling all of them by the same factor is
        a no-op, and only their ratios to a Critical decide anything. Worth
        pinning, because "make everything cost more" is the obvious way to
        attempt a stricter score and it does nothing at all.
        """
        scaled_up = RiskScorer(
            RiskEngineConfig(
                score_deductions={
                    Level.CRITICAL: 40,
                    Level.HIGH: 16,
                    Level.MEDIUM: 6,
                    Level.LOW: 2,
                    Level.UNKNOWN: 6,
                }
            )
        )

        assert scaled_up.security_score([Level.CRITICAL, Level.CRITICAL]) == 60
        assert scaled_up.security_score([Level.HIGH]) == scorer.security_score(
            [Level.HIGH]
        )

    def test_moving_a_band_against_critical_does_change_it(self) -> None:
        """The lever that works: what a High costs *relative to* a Critical."""
        high_hurts = RiskScorer(
            RiskEngineConfig(
                score_deductions={
                    Level.CRITICAL: 20,
                    Level.HIGH: 16,
                    Level.MEDIUM: 3,
                    Level.LOW: 1,
                    Level.UNKNOWN: 3,
                }
            )
        )

        assert high_hurts.security_score([Level.CRITICAL, Level.CRITICAL]) == 60
        assert high_hurts.security_score([Level.HIGH]) < scorer.security_score(
            [Level.HIGH]
        )

    def test_an_anchor_off_the_scale_is_rejected(self) -> None:
        """A curve pinned to 0 or 100 has no solution, and one pinned outside
        them describes nothing. Fail at construction rather than at the first
        scan."""
        with pytest.raises(ValueError, match="strictly between 0 and 100"):
            RiskEngineConfig(score_anchor_value=0.0)
        with pytest.raises(ValueError, match="at least one Critical"):
            RiskEngineConfig(score_anchor_criticals=0)

    def test_the_curve_is_steepest_at_the_first_critical(self) -> None:
        """Where the strictness has to live. The first Critical must cost more
        than the tenth, or a clean estate and a nearly clean one read alike."""
        first = 100 - scorer.security_score([Level.CRITICAL])
        tenth = scorer.security_score([Level.CRITICAL] * 9) - scorer.security_score(
            [Level.CRITICAL] * 10
        )

        assert first > tenth


class TestPriority:
    def test_quick_high_risk_fix_is_critical_priority(self) -> None:
        """Public RDP: High impact, 15 minutes -> top of the list."""
        assert scorer.priority(70, 15) == Priority.CRITICAL

    def test_slow_high_risk_fix_ranks_below_quick_one(self) -> None:
        assert scorer.priority(70, 480) == Priority.HIGH

    def test_slow_medium_risk_is_medium(self) -> None:
        """Logging: Medium impact, 120 minutes."""
        assert scorer.priority(40, 120) == Priority.MEDIUM

    def test_critical_risk_stays_high_even_when_slow(self) -> None:
        assert scorer.priority(90, 2880) == Priority.HIGH
