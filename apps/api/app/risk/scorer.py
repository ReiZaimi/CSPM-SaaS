"""Turning a finding into a scored, prioritized risk.

A finding is a technical observation. A risk is what it means here — on this
asset, with this data, at this level of exposure. The same open RDP port is a
different risk on an isolated dev box than on a production jump host, and this
module is where that difference gets quantified.
"""

from dataclasses import dataclass
from typing import Any

from app.core.enums import Level, Priority, Severity
from app.domain.resource import CloudResource
from app.risk.config import DEFAULT_RISK_CONFIG, RiskEngineConfig


@dataclass(frozen=True)
class RiskInputs:
    severity: Severity
    asset_criticality: Level
    data_sensitivity: Level
    internet_exposure: Level
    exploitability: int


@dataclass(frozen=True)
class ScoredRisk:
    score: float
    level: Level
    business_impact: float
    breakdown: dict[str, Any]
    inputs: RiskInputs


class RiskScorer:
    def __init__(self, config: RiskEngineConfig | None = None) -> None:
        self.config = config or DEFAULT_RISK_CONFIG

    def score(self, inputs: RiskInputs) -> ScoredRisk:
        cfg = self.config
        w = cfg.weights

        severity = cfg.severity_scores[inputs.severity]
        criticality = cfg.level_scores[inputs.asset_criticality]
        sensitivity = cfg.level_scores[inputs.data_sensitivity]
        exposure = cfg.level_scores[inputs.internet_exposure]
        # Clamped rather than trusted: exploitability is a hand-set per-rule tag.
        exploitability = float(max(0, min(5, inputs.exploitability)))

        # Computed, never hand-set (RISK_ENGINE.md section 1).
        business_impact = (criticality + sensitivity) / 2

        components = {
            "severity": (severity, w.severity),
            "asset_criticality": (criticality, w.asset_criticality),
            "data_sensitivity": (sensitivity, w.data_sensitivity),
            "internet_exposure": (exposure, w.internet_exposure),
            "exploitability": (exploitability, w.exploitability),
            "business_impact": (business_impact, w.business_impact),
        }

        weighted_sum = sum(value * weight for value, weight in components.values())
        score = round(weighted_sum * cfg.scale_factor, 2)
        score = max(0.0, min(100.0, score))

        breakdown = {
            name: {
                "value": round(value, 2),
                "weight": weight,
                "contribution": round(value * weight * cfg.scale_factor, 2),
            }
            for name, (value, weight) in components.items()
        }

        return ScoredRisk(
            score=score,
            level=self.band(score),
            business_impact=round(business_impact, 1),
            breakdown={
                "components": breakdown,
                "weighted_sum": round(weighted_sum, 4),
                "scale_factor": cfg.scale_factor,
                "total": score,
            },
            inputs=inputs,
        )

    def band(self, score: float) -> Level:
        for level, low, high in self.config.bands:
            if low <= score <= high:
                return level
        return Level.CRITICAL if score > 0 else Level.LOW

    def security_score(self, open_risk_levels: list[Level]) -> int:
        """Org-level posture, 0-100. Strict on purpose.

        Two open Criticals take 100 down to 60. A CSPM that reports 92/100 while
        a production database is world-readable is not telling the truth.
        """
        deductions = sum(self.config.score_deductions.get(level, 0) for level in open_risk_levels)
        return max(0, 100 - deductions)

    def priority(self, score: float, effort_minutes: int) -> Priority:
        """High impact plus low effort should surface first.

        Raw score alone would bury a fifteen-minute firewall fix underneath an
        architecture redesign that nobody is going to do this quarter
        (RISK_ENGINE.md section 4).
        """
        band = self.band(score)
        quick = effort_minutes <= 30
        slow = effort_minutes > 240

        if band == Level.CRITICAL:
            return Priority.CRITICAL if not slow else Priority.HIGH
        if band == Level.HIGH:
            return Priority.CRITICAL if quick else Priority.HIGH
        if band == Level.MEDIUM:
            return Priority.HIGH if quick else Priority.MEDIUM
        return Priority.MEDIUM if quick else Priority.LOW


def exposure_from_resource(resource: CloudResource | None) -> Level:
    """Internet exposure for scoring purposes.

    An AGGREGATE finding has no resource; that is genuinely unknown exposure,
    and UNKNOWN scores cautiously rather than as LOW.
    """
    if resource is None:
        return Level.UNKNOWN
    return resource.public_exposure


default_scorer = RiskScorer()
