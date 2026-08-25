"""Risk formula (RISK_ENGINE.md section 1) and org security score (section 3)."""

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

    def test_score_floors_at_zero(self) -> None:
        assert scorer.security_score([Level.CRITICAL] * 20) == 0

    def test_mixed_findings(self) -> None:
        # 20 + 8 + 8 + 3 + 1 = 40 deducted.
        levels = [Level.CRITICAL, Level.HIGH, Level.HIGH, Level.MEDIUM, Level.LOW]
        assert scorer.security_score(levels) == 60


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
