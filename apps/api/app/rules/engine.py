"""Rule evaluation.

Takes normalized state, returns verdicts. It touches no database and no cloud
API, which is what makes a scan reproducible: feed the same snapshot in twice
and you get the same findings out.

Two invariants live here, and both matter more than they look:

* A rule that raises is UNKNOWN, never PASS. A crashing rule must degrade
  coverage, not silently declare the environment healthy.
* PASS and NOT_APPLICABLE are counted, not stored per-resource. UNKNOWN is
  stored individually, because each one is a specific thing we failed to check.
"""

from dataclasses import dataclass, field

from app.core.enums import RuleScope, RuleState
from app.domain.resource import CloudResource
from app.rules.base import RuleContext, RuleResult, SecurityRule
from app.rules.registry import enabled_rules


@dataclass
class EvaluatedResult:
    """One verdict, bound to the rule and resource that produced it."""

    rule: SecurityRule
    result: RuleResult
    resource: CloudResource | None = None


@dataclass
class RuleCoverage:
    rule_id: str
    evaluated_count: int = 0
    passed_count: int = 0
    failed_count: int = 0
    unknown_count: int = 0
    not_applicable_count: int = 0

    def record(self, state: RuleState) -> None:
        self.evaluated_count += 1
        attr = {
            RuleState.PASS: "passed_count",
            RuleState.FAIL: "failed_count",
            RuleState.UNKNOWN: "unknown_count",
            RuleState.NOT_APPLICABLE: "not_applicable_count",
        }[state]
        setattr(self, attr, getattr(self, attr) + 1)


@dataclass
class EvaluationReport:
    failures: list[EvaluatedResult] = field(default_factory=list)
    gaps: list[EvaluatedResult] = field(default_factory=list)
    # (rule_id, provider_resource_id) for each PASS. Not persisted per row, but
    # held for the length of the scan: this is what lets a rescan prove a fix
    # and auto-resolve the finding (RULE_ENGINE.md section 3).
    passes: list[tuple[str, str | None]] = field(default_factory=list)
    coverage: dict[str, RuleCoverage] = field(default_factory=dict)
    rules_run: int = 0

    @property
    def coverage_ratio(self) -> float:
        """(passed + failed) / (passed + failed + unknown).

        NOT_APPLICABLE is excluded on purpose: a rule that does not apply is not
        a gap in what we know (RULE_ENGINE.md section 2).
        """
        conclusive = sum(c.passed_count + c.failed_count for c in self.coverage.values())
        unknown = sum(c.unknown_count for c in self.coverage.values())
        total = conclusive + unknown
        return conclusive / total if total else 1.0


class RuleEngine:
    def __init__(self, rules: list[SecurityRule] | None = None) -> None:
        self.rules = rules if rules is not None else enabled_rules()

    def evaluate(self, context: RuleContext) -> EvaluationReport:
        report = EvaluationReport(rules_run=len(self.rules))

        for rule in self.rules:
            coverage = RuleCoverage(rule_id=rule.rule_id)
            report.coverage[rule.rule_id] = coverage

            if rule.scope == RuleScope.AGGREGATE:
                self._run_aggregate(rule, context, report, coverage)
            else:
                self._run_per_resource(rule, context, report, coverage)

        return report

    def _run_per_resource(
        self,
        rule: SecurityRule,
        context: RuleContext,
        report: EvaluationReport,
        coverage: RuleCoverage,
    ) -> None:
        for resource in context.resources:
            if not rule.matches(resource):
                continue
            for result in self._safe_evaluate(rule, resource, context):
                self._record(rule, result, resource, report, coverage)

    def _run_aggregate(
        self,
        rule: SecurityRule,
        context: RuleContext,
        report: EvaluationReport,
        coverage: RuleCoverage,
    ) -> None:
        for result in self._safe_evaluate(rule, None, context):
            # An AGGREGATE rule may name a specific resource in its result; if
            # it does, we attribute the verdict to that resource.
            resource = (
                context.get_resource(result.resource_id) if result.resource_id else None
            )
            self._record(rule, result, resource, report, coverage)

    def _safe_evaluate(
        self, rule: SecurityRule, resource: CloudResource | None, context: RuleContext
    ) -> list[RuleResult]:
        try:
            outcome = rule.evaluate(resource, context)
        except Exception as exc:
            return [
                RuleResult.unknown(
                    f"Rule {rule.rule_id} raised {type(exc).__name__}: {exc}"
                )
            ]
        if isinstance(outcome, RuleResult):
            return [outcome]
        return list(outcome)

    def _record(
        self,
        rule: SecurityRule,
        result: RuleResult,
        resource: CloudResource | None,
        report: EvaluationReport,
        coverage: RuleCoverage,
    ) -> None:
        coverage.record(result.state)
        evaluated = EvaluatedResult(rule=rule, result=result, resource=resource)

        if result.state == RuleState.FAIL:
            report.failures.append(evaluated)
        elif result.state == RuleState.PASS:
            report.passes.append(
                (rule.rule_id, resource.provider_resource_id if resource else None)
            )
        elif result.state == RuleState.UNKNOWN:
            # Tracked for coverage. Never becomes a Finding -- a Finding means
            # "we observed something wrong", and we observed nothing here.
            report.gaps.append(evaluated)
