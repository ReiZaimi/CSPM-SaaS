"""Turning a finding into a scored, prioritized risk.

A finding is a technical observation. A risk is what it means here — on this
asset, with this data, at this level of exposure. The same open RDP port is a
different risk on an isolated dev box than on a production jump host, and this
module is where that difference gets quantified.
"""

import math
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
    # The same finding scored over what CloudGuard actually established, with
    # every UNKNOWN input taken at the bottom of the scale instead of just under
    # High. Always less than or equal to ``score``, and equal to it whenever the
    # asset's context is fully known.
    #
    # Two numbers because they answer two questions. ``score`` ranks: an
    # unclassified production database must not sort below a tagged dev box, so
    # missing context is treated cautiously. This one is what CloudGuard can
    # *demonstrate*, and it is what the org security score charges for -- a
    # posture number moved by CloudGuard's own blind spots is measuring the
    # wrong thing (RISK_ENGINE.md section 3).
    #
    # ``None`` where the question does not apply. A scenario is a statement
    # about a route rather than about one asset's context, and it never reaches
    # the org score, so inventing a second number for it would be a claim
    # nobody made.
    known_score: float | None = None
    known_level: Level | None = None


class RiskScorer:
    def __init__(self, config: RiskEngineConfig | None = None) -> None:
        self.config = config or DEFAULT_RISK_CONFIG

    def _level_value(self, level: Level, *, cautious: bool) -> float:
        """What a context level is worth to the formula.

        ``cautious`` is how a finding is *ranked*: UNKNOWN scores just under
        High, so an unclassified asset never sorts below one somebody labelled
        as unimportant. Without it, the cheapest way to look secure would be to
        tag nothing.

        The other reading is what CloudGuard can *demonstrate*: UNKNOWN takes
        the bottom of the scale, because "we could not work this out" is not
        evidence of anything. Not zero -- an asset is at least a low-criticality
        asset -- and never used for ranking.
        """
        if level is Level.UNKNOWN and not cautious:
            return self.config.level_scores[Level.LOW]
        return self.config.level_scores[level]

    def score(self, inputs: RiskInputs) -> ScoredRisk:
        cfg = self.config
        w = cfg.weights

        severity = cfg.severity_scores[inputs.severity]
        criticality = self._level_value(inputs.asset_criticality, cautious=True)
        sensitivity = self._level_value(inputs.data_sensitivity, cautious=True)
        exposure = self._level_value(inputs.internet_exposure, cautious=True)
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

        known_score = self._known_score(inputs, severity, exploitability)

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
                # Recorded beside the arithmetic it differs from, so a customer
                # asking why the org score did not fall as far as this risk
                # suggests has the second number in front of them rather than
                # having to be told a rule exists.
                "known_total": known_score,
            },
            inputs=inputs,
            known_score=known_score,
            known_level=self.band(known_score),
        )

    def _known_score(
        self, inputs: RiskInputs, severity: float, exploitability: float
    ) -> float:
        """The same formula over established context only.

        A second pass rather than a scaling of the first: the weights are not
        uniform, so which component was unknown changes how much it mattered,
        and a blanket discount would get that wrong in both directions.
        """
        cfg = self.config
        w = cfg.weights
        criticality = self._level_value(inputs.asset_criticality, cautious=False)
        sensitivity = self._level_value(inputs.data_sensitivity, cautious=False)
        exposure = self._level_value(inputs.internet_exposure, cautious=False)
        business_impact = (criticality + sensitivity) / 2

        weighted_sum = (
            severity * w.severity
            + criticality * w.asset_criticality
            + sensitivity * w.data_sensitivity
            + exposure * w.internet_exposure
            + exploitability * w.exploitability
            + business_impact * w.business_impact
        )
        return max(0.0, min(100.0, round(weighted_sum * cfg.scale_factor, 2)))

    def band(self, score: float) -> Level:
        for level, low, high in self.config.bands:
            if low <= score <= high:
                return level
        return Level.CRITICAL if score > 0 else Level.LOW

    def scenario_score(
        self,
        member_scores: list[float],
        *,
        hops: int,
        entry_exposure: Level,
        target_sensitivity: Level,
    ) -> ScoredRisk:
        """What a route is worth, given what is already known about its parts.

        Built on top of the members rather than beside them. The worst finding
        on the path is the floor: a scenario cannot be less serious than the
        most serious thing in it, and a formula that could would let a route
        through a critical misconfiguration rank below that misconfiguration
        alone.

        The amplifier is what the *combination* adds, and it is bounded and
        mostly about length. That bound is deliberate. An unbounded structural
        term would let a long chain of ordinary facts outrank a genuinely
        critical finding, which is how a risk score stops meaning anything --
        and the members are the evidence here, while this is only the
        observation that they join up.

        Deliberately no probability. Calibrating one needs breach outcomes that
        will never exist here, and an uncalibrated probability is a weighted
        sum wearing a costume (RISK_ENGINE.md, ARCHITECTURE_REVIEW.md section 9).
        """
        cfg = self.config
        floor = max(member_scores) if member_scores else 0.0

        # Shortness, then the two things that decide whether the ends are worth
        # joining at all.
        shortness = max(0.0, cfg.max_scenario_amplifier - (hops - 1) * cfg.scenario_hop_penalty)
        ends = (
            cfg.level_scores[entry_exposure] + cfg.level_scores[target_sensitivity]
        ) / 10.0
        amplifier = min(cfg.max_scenario_amplifier, shortness * ends)

        uncapped = floor + amplifier
        score = round(min(100.0, uncapped), 2)
        inputs = RiskInputs(
            severity=Severity.HIGH,
            asset_criticality=Level.UNKNOWN,
            data_sensitivity=target_sensitivity,
            internet_exposure=entry_exposure,
            exploitability=0,
        )
        return ScoredRisk(
            score=score,
            level=self.band(score),
            business_impact=round(cfg.level_scores[target_sensitivity], 1),
            breakdown={
                # Every term named, so "why is this 91?" is answerable without
                # rerunning anything -- and so the floor is visibly the members'
                # rather than something this function decided.
                "worst_member": round(floor, 2),
                "amplifier": round(amplifier, 2),
                "hops": hops,
                "shortness": round(shortness, 2),
                "ends": round(ends, 3),
                "amplifier_cap": cfg.max_scenario_amplifier,
                # Recorded so the ceiling explains itself. Without it a
                # scenario that came to 101 and shows 100 leaves the terms
                # visibly not adding up, which is worse than not showing them.
                "uncapped": round(uncapped, 2),
                "total": score,
            },
            inputs=inputs,
        )

    def security_score(self, open_risk_levels: list[Level]) -> int:
        """Org-level posture, 0-100. Strict on purpose, and never flat.

        Two open Criticals take 100 down to 60. A CSPM that reports 92/100 while
        a production database is world-readable is not telling the truth.

        **Decay rather than subtraction.** The deductions used to be taken off
        100 and clamped at zero, which made the number stop moving exactly where
        it needed to move most: an estate with five open Criticals scored 0, and
        so did one with twenty, and so did the same estate after seven of them
        were fixed. A customer working through a remediation programme watched a
        flat line for months, on the product whose north-star metric is verified
        risk reduction -- and the dashboard's delta, computed from that number,
        reported nothing had happened.

        So the same deduction total drives an exponential instead. Every fix
        moves the score, the curve is steepest where the first few Criticals
        are, and zero is where a catastrophic estate ends up rather than where
        an ordinarily bad one starts. The anchor everyone already agreed --
        two Criticals leave 60 -- is preserved exactly; it is what the curve is
        fitted to (RISK_ENGINE.md section 3).

        Rounded to a whole number because the score is read, not computed with.
        Far enough out the rounding does flatten it, but by then the estate has
        twenty open Criticals and the number has said what it has to say.
        """
        deductions = sum(self.config.score_deductions.get(level, 0) for level in open_risk_levels)
        return round(100.0 * math.exp(-deductions / self.config.score_decay))

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
