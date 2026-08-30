"""Risk engine configuration.

Every number the risk formula uses lives here, not inside rule logic
(PRODUCT_SPEC.md requirement 12). The spec is explicit that these are starting
values to be tuned against real environments — which is only possible if they
are in one place with names attached.
"""

from dataclasses import dataclass, field

from app.core.enums import Level, Severity


@dataclass(frozen=True)
class RiskWeights:
    severity: float = 0.25
    asset_criticality: float = 0.20
    data_sensitivity: float = 0.15
    internet_exposure: float = 0.20
    exploitability: float = 0.10
    business_impact: float = 0.10

    def total(self) -> float:
        return (
            self.severity
            + self.asset_criticality
            + self.data_sensitivity
            + self.internet_exposure
            + self.exploitability
            + self.business_impact
        )


@dataclass(frozen=True)
class RiskEngineConfig:
    weights: RiskWeights = field(default_factory=RiskWeights)

    # Components are normalized 0-5, then the weighted sum is multiplied by 20
    # to land on 0-100.
    scale_factor: float = 20.0

    level_scores: dict[Level, float] = field(
        default_factory=lambda: {
            Level.LOW: 1.0,
            Level.MEDIUM: 2.5,
            Level.HIGH: 4.0,
            Level.CRITICAL: 5.0,
            # Cautious by design: just under HIGH, so missing context never
            # reads as low risk. Applied to criticality, sensitivity AND
            # exposure alike (RISK_ENGINE.md section 1).
            Level.UNKNOWN: 3.5,
        }
    )

    severity_scores: dict[Severity, float] = field(
        default_factory=lambda: {
            Severity.LOW: 1.0,
            Severity.MEDIUM: 2.5,
            Severity.HIGH: 4.0,
            Severity.CRITICAL: 5.0,
        }
    )

    # Risk bands over the 0-100 score. Lower bound inclusive, upper inclusive.
    bands: tuple[tuple[Level, float, float], ...] = (
        (Level.LOW, 0.0, 24.0),
        (Level.MEDIUM, 25.0, 49.0),
        (Level.HIGH, 50.0, 74.0),
        (Level.CRITICAL, 75.0, 100.0),
    )

    # Org security score deductions, keyed off each finding's risk BAND rather
    # than the rule's raw severity: the same misconfiguration on a dev VM and a
    # production database should not cost the same (RISK_ENGINE.md section 3).
    score_deductions: dict[Level, int] = field(
        default_factory=lambda: {
            Level.CRITICAL: 20,
            Level.HIGH: 8,
            Level.MEDIUM: 3,
            Level.LOW: 1,
            Level.UNKNOWN: 3,
        }
    )

    # How much a scenario may add on top of its worst member, and what earns
    # it. Bounded so a path can never dominate the score on structure alone:
    # the members are the evidence, and this is the fact that they compose.
    #
    # Shortness is the dominant term because it is the honest one. A two-hop
    # route from an exposed host to sensitive data is both likelier to be
    # walked and cheaper to describe than a five-hop one, and every hop is
    # another thing that has to hold for the route to be real.
    max_scenario_amplifier: float = 25.0
    # Subtracted per hop beyond the first, so a long chain converges on adding
    # nothing rather than on adding a lot slowly.
    scenario_hop_penalty: float = 6.0

    def __post_init__(self) -> None:
        total = self.weights.total()
        if abs(total - 1.0) > 1e-9:
            raise ValueError(f"Risk weights must sum to 1.0, got {total}")


DEFAULT_RISK_CONFIG = RiskEngineConfig()
