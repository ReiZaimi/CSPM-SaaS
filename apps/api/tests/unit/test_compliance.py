"""Framework catalogue integrity and per-control status resolution.

The first half is the test that actually earns its place. Rules reference
controls as bare strings; nothing in Python checks that ``A.8.20`` is a control
that exists. A typo there does not fail -- it quietly produces a control nobody
can find and a rule whose evidence goes nowhere, which in a compliance view is
the kind of wrong that gets believed.
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.compliance.catalog import FRAMEWORKS, get_framework
from app.compliance.coverage import (
    ControlStatus,
    RuleEvidence,
    coverage_ratio,
    resolve_control_status,
    status_counts,
    summarize_readings,
)
from app.rules.registry import RULE_REGISTRY

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)


def evidence(
    rule_id: str = "AZ-NET-001",
    *,
    open_findings: int = 0,
    unknown: int = 0,
    evaluated: bool = True,
) -> RuleEvidence:
    return RuleEvidence(
        rule_id=rule_id,
        name="A rule",
        severity="HIGH",
        open_finding_count=open_findings,
        unknown_count=unknown,
        evaluated=evaluated,
    )


# --- catalogue integrity ---------------------------------------------------


def test_every_control_a_rule_references_exists_in_the_catalogue() -> None:
    """The drift guard. A rule mapped to a control the catalogue does not know
    renders as nothing at all, so this must fail at test time instead."""
    unknown: list[str] = []

    for rule in RULE_REGISTRY:
        for framework_id, control_ids in rule.compliance_mappings.items():
            framework = get_framework(framework_id)
            if framework is None:
                unknown.append(f"{rule.rule_id}: unknown framework {framework_id}")
                continue
            for control_id in control_ids:
                if framework.control(control_id) is None:
                    unknown.append(f"{rule.rule_id}: {framework_id} has no control {control_id}")

    assert unknown == []


def test_catalogue_lists_controls_no_rule_covers() -> None:
    """A catalogue of only what CloudGuard checks would report full coverage
    forever. The gaps are the point of the page."""
    mapped = {
        (framework_id, control_id)
        for rule in RULE_REGISTRY
        for framework_id, control_ids in rule.compliance_mappings.items()
        for control_id in control_ids
    }

    for framework in FRAMEWORKS:
        uncovered = [c for c in framework.controls if (framework.id, c.id) not in mapped]
        assert uncovered, f"{framework.id} claims complete coverage"


def test_frameworks_requested_by_the_product_are_present() -> None:
    ids = {f.id for f in FRAMEWORKS}
    assert {"CIS_AZURE_2.0", "ISO_27001", "GDPR"} <= ids


def test_every_framework_cites_its_source() -> None:
    """Titles here are CloudGuard's own words, so the link to the authoritative
    text is not decoration -- it is the only way to check a control's meaning."""
    for framework in FRAMEWORKS:
        assert framework.url.startswith("https://")
        assert framework.authority
        assert framework.scope_note


# --- status resolution -----------------------------------------------------


def test_no_mapped_rule_is_not_covered() -> None:
    assert resolve_control_status([], has_completed_scan=True) == ControlStatus.NOT_COVERED


def test_mapped_but_never_scanned_is_not_assessed() -> None:
    status = resolve_control_status([evidence(evaluated=False)], has_completed_scan=False)
    assert status == ControlStatus.NOT_ASSESSED


def test_open_finding_fails_the_control() -> None:
    status = resolve_control_status([evidence(open_findings=2)], has_completed_scan=True)
    assert status == ControlStatus.FAILING


def test_one_failing_rule_beats_four_passing_ones() -> None:
    """Controls are met or not met. Partial credit would let a real
    misconfiguration hide behind its neighbours."""
    status = resolve_control_status(
        [evidence("A"), evidence("B"), evidence("C"), evidence("D", open_findings=1)],
        has_completed_scan=True,
    )
    assert status == ControlStatus.FAILING


def test_unknown_is_inconclusive_not_passing() -> None:
    """The whole ethos, in a compliance view: a storage API that timed out must
    never read as "your storage controls are met"."""
    status = resolve_control_status([evidence(unknown=3)], has_completed_scan=True)
    assert status == ControlStatus.INCONCLUSIVE


def test_a_control_whose_rules_all_missed_the_scan_is_not_assessed() -> None:
    """Distinct from INCONCLUSIVE on purpose: nothing looked at this control at
    all, which is a different thing from looking and failing to tell."""
    status = resolve_control_status([evidence(evaluated=False)], has_completed_scan=True)
    assert status == ControlStatus.NOT_ASSESSED


def test_one_rule_missing_from_the_scan_makes_the_control_inconclusive() -> None:
    """Here something did run, so the control was assessed -- just not fully,
    and a partial look is not a pass."""
    status = resolve_control_status(
        [evidence("A"), evidence("B", evaluated=False)], has_completed_scan=True
    )
    assert status == ControlStatus.INCONCLUSIVE


def test_failing_outranks_inconclusive() -> None:
    status = resolve_control_status(
        [evidence("A", unknown=5), evidence("B", open_findings=1)],
        has_completed_scan=True,
    )
    assert status == ControlStatus.FAILING


def test_all_conclusive_and_clean_passes() -> None:
    status = resolve_control_status([evidence("A"), evidence("B")], has_completed_scan=True)
    assert status == ControlStatus.PASSING


# --- aggregates ------------------------------------------------------------


def test_coverage_counts_conclusions_not_passes() -> None:
    """Coverage answers "how much can CloudGuard speak to", not "how compliant
    are you" -- a failing control is covered, an unknown one is not."""
    ratio = coverage_ratio(
        [
            ControlStatus.PASSING,
            ControlStatus.FAILING,
            ControlStatus.INCONCLUSIVE,
            ControlStatus.NOT_COVERED,
        ]
    )
    assert ratio == pytest.approx(0.5)


def test_coverage_of_nothing_is_none_not_zero() -> None:
    assert coverage_ratio([]) is None


def test_status_counts_include_absent_statuses() -> None:
    counts = status_counts([ControlStatus.PASSING])
    assert counts["PASSING"] == 1
    assert counts["FAILING"] == 0
    assert set(counts) == {s.value for s in ControlStatus}


def test_no_framework_text_carries_markup_the_page_renders_literally() -> None:
    """These strings are shown as text, not parsed.

    ``ComplianceFramework.tsx`` renders ``{data.scope_note}`` straight into
    JSX, so a ``**`` written for emphasis reaches the customer as two
    asterisks. Caught here rather than by eye, because the place a caveat most
    wants emphasis -- PCI's, about scope it cannot know -- is exactly where
    somebody reaches for markdown, and where a stray asterisk reads as sloppy
    on the page that most needs to be believed.
    """
    offenders = []
    for framework in FRAMEWORKS:
        text = f"{framework.summary} {framework.scope_note} {framework.name}"
        text += " " + " ".join(c.title for c in framework.controls)
        for markup in ("**", "__", "`", "<"):
            if markup in text:
                offenders.append(f"{framework.id}: {markup!r}")
    assert offenders == [], (
        "these render as literal characters rather than formatting: "
        f"{offenders}"
    )



# ------------------------------------------------ the readings under a control
class TestReadingsBehindAControl:
    """How CloudGuard knows a control is *met*, which is the harder half.

    A finding cites the readings behind it, so "how do you know this is wrong"
    has always been answerable. A passing control has no findings, so it had no
    citations at all -- a green row asserted on nothing, which is exactly the
    row an auditor asks about first.
    """

    @staticmethod
    def _row(
        key: str,
        outcome: str = "COMPLETE",
        *,
        hours: int = 1,
        permissions: tuple[str, ...] = ("Microsoft.Storage/storageAccounts/read",),
        content_hash: str | None = "a" * 64,
    ) -> tuple:
        return (key, outcome, NOW - timedelta(hours=hours), permissions, content_hash)

    def test_a_reading_is_one_entry_however_many_subscriptions_it_covered(self) -> None:
        """Fifty subscriptions read storage fifty times, and fifty identical
        rows under one control is a table nobody reads."""
        readings = summarize_readings(
            ["storage_accounts"],
            [self._row("storage_accounts") for _ in range(50)],
            frozenset({"a" * 64}),
        )

        assert len(readings) == 1
        assert readings[0].scopes == 50

    def test_the_worst_outcome_wins(self) -> None:
        """A listing truncated in one subscription out of nine cannot support
        "none of them are public" -- the same reason PARTIAL is not a pass one
        layer below this."""
        readings = summarize_readings(
            ["storage_accounts"],
            [
                self._row("storage_accounts", "COMPLETE"),
                self._row("storage_accounts", "PARTIAL"),
                self._row("storage_accounts", "COMPLETE"),
            ],
        )

        assert readings[0].outcome == "PARTIAL"

    def test_a_failure_outranks_a_truncation(self) -> None:
        readings = summarize_readings(
            ["storage_accounts"],
            [
                self._row("storage_accounts", "PARTIAL"),
                self._row("storage_accounts", "FAILED"),
            ],
        )

        assert readings[0].outcome == "FAILED"

    def test_the_oldest_read_is_the_one_reported(self) -> None:
        """A control is only as current as the least current thing it rests on.
        Taking the newest would let forty-nine fresh subscriptions hide the one
        nobody has read since Tuesday."""
        readings = summarize_readings(
            ["storage_accounts"],
            [
                self._row("storage_accounts", hours=1),
                self._row("storage_accounts", hours=200),
            ],
        )

        assert readings[0].collected_at == NOW - timedelta(hours=200)

    def test_a_key_nothing_read_is_still_listed(self) -> None:
        """The case that matters most, and the one an omission would hide: the
        verdict above rests on a reading nobody took. Reported as no outcome
        rather than as a failure -- the provider did not refuse, nothing
        asked."""
        readings = summarize_readings(["key_vaults"], [])

        assert len(readings) == 1
        assert readings[0].outcome is None
        assert readings[0].collected_at is None
        assert readings[0].scopes == 0

    def test_permissions_are_reported_once_across_scopes(self) -> None:
        """"Under what permission did you see this" is one answer, not fifty."""
        readings = summarize_readings(
            ["storage_accounts"],
            [
                self._row("storage_accounts", permissions=("A/read",)),
                self._row("storage_accounts", permissions=("A/read", "B/read")),
            ],
        )

        assert readings[0].permissions == ("A/read", "B/read")

    def test_a_pruned_payload_is_reported_as_no_longer_followable(self) -> None:
        """The citation stays true and the bytes are gone. Retention prunes
        payloads long before the record that they were read, and offering a link
        that fails would be worse than saying so."""
        readings = summarize_readings(
            ["storage_accounts"],
            [self._row("storage_accounts", content_hash="b" * 64)],
            frozenset({"a" * 64}),
        )

        assert readings[0].retained is False

    def test_one_pruned_payload_makes_the_whole_reading_unfollowable(self) -> None:
        """Nine readings of which one has aged out cannot be followed all the
        way back, and "partly retained" is honestly reported as no."""
        readings = summarize_readings(
            ["storage_accounts"],
            [
                self._row("storage_accounts", content_hash="a" * 64),
                self._row("storage_accounts", content_hash="c" * 64),
            ],
            frozenset({"a" * 64}),
        )

        assert readings[0].retained is False
