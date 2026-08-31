"""What a report is allowed to say, and what it must never leave out.

A PDF outlives the screen it was taken from and nobody can ask it a follow-up
question, so the caveats the UI can afford to put behind a tooltip have to be
printed. These tests are mostly about that: coverage gaps, collection failures,
the age of the evidence, and the difference between "no earlier reading" and
"no change".

They assert against the HTML rather than the PDF on purpose. The PDF is that
HTML printed by WeasyPrint, which needs native libraries a developer machine
may not have -- so the layer worth pinning is the one that decides what the
document says.
"""

from datetime import UTC, datetime

import pytest

from app.reports.chart import VIEW_HEIGHT, score_trend_svg
from app.reports.render import render_html
from app.services.reports import OPTIONAL_SECTIONS, _evidence, _posture


def body(html: str) -> str:
    """The document without its stylesheet.

    The CSS is full of lengths like ``100%`` and colours like ``#fef2f2``, so a
    naive substring assertion over the whole file matches things no reader ever
    sees.
    """
    return html.split("</style>", 1)[-1]


def dashboard(**overrides) -> dict:
    base = {
        "security_score": 84,
        "score_delta": 7,
        "history": [],
        "findings_by_severity": {"LOW": 4, "CRITICAL": 1, "HIGH": 2},
        "findings_by_status": {"OPEN": 7, "RESOLVED": 3},
        "risk_bands": {},
        "open_finding_count": 7,
        "asset_count": 42,
        "verified_resolved_last_30_days": 3,
        "remediation_rate": 0.3,
        "top_risks": [
            {
                "id": "r-1",
                "title": "Production database publicly accessible",
                "risk_score": 92.4,
                "risk_level": "CRITICAL",
            }
        ],
        "coverage": {"ratio": 0.8, "unknown": 3, "conclusive": 12},
        "evidence_freshness": {
            "readings": 10,
            "oldest_at": "2026-08-30T09:00:00+00:00",
            "newest_at": "2026-08-31T09:00:00+00:00",
            "stale_hours": 24.0,
            "unusable": 0,
        },
        "last_scan": {
            "id": "s-1",
            "status": "COMPLETED",
            "completed_at": "2026-08-31T09:00:00+00:00",
            "resource_count": 42,
            "rule_count": 30,
            "finding_count": 7,
            "collection_errors": {},
        },
    }
    base.update(overrides)
    return base


def report(**overrides) -> dict:
    data = dashboard(**overrides.pop("dashboard", {}))
    base = {
        "generated_at": datetime(2026, 8, 31, 12, 0, tzinfo=UTC).isoformat(),
        "organization": {"name": "Contoso", "industry": None, "country": "AL"},
        "kind": "executive",
        "sections": list(OPTIONAL_SECTIONS),
        "omitted_sections": [],
        "window_days": 30,
        # An early cutoff, so a fixture's readings are all inside the window
        # unless a test is specifically about the window.
        "posture": _posture(data, since=datetime(2026, 1, 1, tzinfo=UTC)),
        "evidence": _evidence(data),
        "top_risks": data["top_risks"],
        "attack_paths": [
            {
                "entry": "vm-jump-01",
                "target": "prodstorage",
                "hops": 2,
                "steps": [
                    "vm-jump-01 runs as mi-jump",
                    "mi-jump can act over prodstorage",
                ],
                "cheapest_break": "mi-jump can act over prodstorage",
            }
        ],
        "remediation": {
            "open_tasks": 4,
            "done_tasks": 6,
            "cancelled_tasks": 0,
            "completed_in_window": 2,
            "remediation_rate": 0.3,
        },
        "compliance": {
            "frameworks": [
                {
                    "short_name": "ISO 27001",
                    "version": "2022",
                    "control_count": 20,
                    "coverage_ratio": 0.4,
                    "open_finding_count": 3,
                }
            ],
            "disclaimer": "This is evidence, not a compliance verdict.",
        },
    }
    base.update(overrides)
    return base


# --- what the numbers are worth -------------------------------------------


def test_unknown_checks_are_named_and_are_not_a_pass():
    # The transformation this whole product exists to refuse. A report that
    # drops the checks that reached no verdict turns "we could not look" into
    # "we looked and it was fine".
    html = render_html(report())

    assert "3 checks" in html
    assert "never counted as a pass" in html


def test_a_report_over_stale_evidence_says_so_before_the_score():
    html = render_html(
        report(dashboard={"evidence_freshness": {"stale_hours": 72.0, "oldest_at": None,
                                                 "newest_at": None, "unusable": 0}})
    )

    warning = html.index("has not been read recently")
    score = html.index("Security posture")
    # Before, not in an appendix: by the time a reader reaches a footnote they
    # have already believed the headline.
    assert warning < score


def test_fresh_evidence_carries_no_staleness_warning():
    html = render_html(report())

    assert "has not been read recently" not in html


def test_collection_failures_travel_with_the_numbers():
    html = render_html(
        report(
            dashboard={
                "last_scan": {
                    **dashboard()["last_scan"],
                    "collection_errors": {"sub-1": "Reader role missing on the subscription"},
                }
            }
        )
    )

    assert "could not be read" in html
    assert "Reader role missing on the subscription" in html


def test_no_earlier_reading_is_not_reported_as_no_change():
    # Opposite meanings to somebody deciding whether remediation is working.
    html = render_html(report(dashboard={"score_delta": None}))

    assert "no earlier reading to compare against" in html


def test_severity_is_ordered_by_seriousness_not_by_the_query():
    html = render_html(report())

    assert html.index("Critical") < html.index("High") < html.index("Low")


def test_a_framework_with_nothing_assessed_is_not_reported_as_zero_percent():
    html = render_html(
        report(
            compliance={
                "frameworks": [
                    {
                        "short_name": "NIST CSF",
                        "version": "2.0",
                        "control_count": 20,
                        "coverage_ratio": None,
                        "open_finding_count": 0,
                    }
                ],
                "disclaimer": "This is evidence, not a compliance verdict.",
            }
        )
    )

    compliance = body(html).split("Compliance coverage", 1)[-1]
    assert "0%" not in compliance
    # An em dash, meaning "nothing assessed" — which is not a failing grade.
    assert "—" in compliance


def test_the_compliance_disclaimer_is_printed_in_the_document():
    # It gets forwarded to auditors and boards without the screen it came from.
    html = render_html(report())

    assert "not a compliance verdict" in html


# --- the two reports -------------------------------------------------------


def test_the_executive_report_does_not_list_findings():
    # An executive summary ending in a four-hundred-row table is a technical
    # report with a cover page.
    html = render_html(report())

    assert "Open findings</h2>" not in html
    assert "Production database publicly accessible" in html


def test_the_technical_report_lists_findings_and_names_a_truncation():
    html = render_html(
        report(
            kind="technical",
            findings=[
                {
                    "id": "f-1",
                    "rule_id": "AZ-STO-001",
                    "title": "Storage account allows public blob access",
                    "severity": "CRITICAL",
                    "status": "OPEN",
                    "risk_score": 84.0,
                    "first_detected_at": "2026-08-01T09:00:00+00:00",
                    "last_detected_at": "2026-08-31T09:00:00+00:00",
                    "remediation": "Set allowBlobPublicAccess to false.",
                    "asset": {
                        "name": "customerdata",
                        "resource_type": "storage_account",
                        "environment": "production",
                        "region": "westeurope",
                    },
                }
            ],
            finding_total=4000,
            findings_truncated=True,
        )
    )

    assert "Storage account allows public blob access" in html
    assert "customerdata" in html
    assert "Set allowBlobPublicAccess to false." in html
    # A document quietly showing 1 of 4000 is not a shorter report.
    assert "4000" in html
    assert "highest-risk" in html


def test_a_finding_whose_asset_is_gone_says_so_rather_than_rendering_blank():
    html = render_html(
        report(
            kind="technical",
            findings=[
                {
                    "id": "f-1",
                    "rule_id": "AZ-STO-001",
                    "title": "Orphaned finding",
                    "severity": "HIGH",
                    "status": "OPEN",
                    "risk_score": None,
                    "first_detected_at": "2026-08-01T09:00:00+00:00",
                    "last_detected_at": "2026-08-31T09:00:00+00:00",
                    "remediation": "",
                    "asset": None,
                }
            ],
            finding_total=1,
            findings_truncated=False,
        )
    )

    assert "no longer in the inventory" in html


# --- rendering safety ------------------------------------------------------


def test_a_resource_named_like_markup_renders_as_a_name():
    # Every string in a report comes from a customer's own cloud.
    html = render_html(
        report(
            kind="technical",
            findings=[
                {
                    "id": "f-1",
                    "rule_id": "AZ-STO-001",
                    "title": "<script>alert(1)</script>",
                    "severity": "HIGH",
                    "status": "OPEN",
                    "risk_score": None,
                    "first_detected_at": "2026-08-01T09:00:00+00:00",
                    "last_detected_at": "2026-08-31T09:00:00+00:00",
                    "remediation": "",
                    "asset": None,
                }
            ],
            finding_total=1,
            findings_truncated=False,
        )
    )

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_a_report_fetches_nothing_when_it_renders():
    # No web fonts, no images, no external stylesheet: a report has to render
    # identically on a server with no network, and nothing a customer can name
    # may cause an outbound request.
    html = render_html(report())

    assert "http://" not in html
    assert "https://" not in html


@pytest.mark.parametrize("kind", ["executive", "technical"])
def test_both_reports_carry_the_same_posture_block(kind: str):
    # Two pages of one report disagreeing about the score is the first thing
    # anybody notices, and the last thing they forgive.
    html = render_html(report(kind=kind, findings=[], finding_total=0,
                              findings_truncated=False))

    assert "84" in html
    assert "Assets under assessment" in html


# --- the trend ------------------------------------------------------------


def readings(*scores: int) -> list[dict]:
    return [
        {"observed_at": f"2026-08-{day + 1:02d}T09:00:00+00:00", "security_score": score}
        for day, score in enumerate(scores)
    ]


def test_one_reading_draws_no_trend():
    # A line through a single point invites the reader to see a direction
    # nobody has measured.
    assert score_trend_svg(readings(84)) == ""
    assert score_trend_svg([]) == ""


def test_a_trend_is_drawn_on_a_fixed_scale_not_a_fitted_one():
    # Fitting the axis to the observed range is the most common way a
    # sparkline lies: a wobble would climb as steeply as a real recovery.
    wobble = score_trend_svg(readings(81, 84))
    climb = score_trend_svg(readings(20, 84))

    def last_y(svg: str) -> float:
        return float(svg.split('<circle cx="')[1].split('cy="')[1].split('"')[0])

    def first_y(svg: str) -> float:
        return float(svg.split('<polyline points="')[1].split(",")[1].split(" ")[0])

    # Same endpoint on both, because both end at 84 on a 0-100 scale.
    assert last_y(wobble) == pytest.approx(last_y(climb))
    # And a genuinely different start.
    assert first_y(climb) > first_y(wobble)


def test_a_score_outside_the_scale_is_clamped_rather_than_drawn_off_the_chart():
    svg = score_trend_svg(readings(-10, 140))

    ys = [float(pair.split(",")[1]) for pair in
          svg.split('<polyline points="')[1].split('"')[0].split(" ")]
    assert all(0 <= y <= VIEW_HEIGHT for y in ys)


def test_the_report_draws_the_trend_when_there_is_one():
    html = render_html(report(dashboard={"history": readings(60, 72, 84)}))

    assert "<svg" in html
    assert "across the 3 readings" in html
    # The window is named beside the count, because a line drawn over the last
    # 30 days and one drawn over the last year are different claims.
    assert "last 30 days" in html


def test_the_trend_is_cut_to_the_window_it_was_asked_for():
    # A report asked for the last week must not draw a line reaching back six
    # months: the sparkline is the evidence for "is this improving", and its
    # period has to be the period the reader chose.
    posture = _posture(
        dashboard(history=readings(60, 72, 84)),
        window_days=7,
        since=datetime(2026, 8, 3, tzinfo=UTC),
    )

    assert [entry["security_score"] for entry in posture["history"]] == [84]


def test_the_report_draws_no_trend_from_a_single_reading():
    html = render_html(report(dashboard={"history": readings(84)}))

    assert "<svg" not in html


# --- accepted risk ---------------------------------------------------------


def test_an_accepted_risk_is_counted_rather_than_absorbed_into_not_open():
    # A finding somebody decided to live with is still in the environment.
    # Silently excluding it lets a report claim an estate that is clean by
    # decision rather than by remediation.
    html = render_html(
        report(dashboard={"findings_by_status": {"OPEN": 7, "ACCEPTED_RISK": 4}})
    )

    assert "accepted as risk" in html
    assert "not a fix" in html


def test_nothing_is_said_about_accepted_risk_when_there_is_none():
    html = render_html(report())

    assert "accepted as risk" not in html

# --- what a reader chose to leave in ---------------------------------------


def test_a_section_left_out_is_named_rather_than_silently_absent():
    # An omission somebody chose looks exactly like an absence of evidence once
    # a PDF has been forwarded twice, and only one of those is true.
    html = render_html(
        report(
            sections=["top_risks", "attack_paths", "remediation"],
            omitted_sections=["compliance coverage"],
        )
    )

    assert "Sections excluded from this report" in html
    assert "Compliance coverage" in html
    assert "Compliance coverage</h2>" not in html


def test_the_posture_and_the_caveats_cannot_be_switched_off():
    # The parts that say what the numbers are worth are not optional: a report
    # that could drop "12% of checks reached no verdict" would let somebody
    # produce a cleaner-looking document by unticking a box.
    html = render_html(report(sections=[], omitted_sections=["top risks"]))

    assert "Security posture" in html
    assert "3 checks" in html
    assert "never counted as a pass" in html


def test_attack_paths_name_the_route_and_the_link_to_cut():
    html = render_html(report())

    assert "vm-jump-01 → prodstorage" in html
    assert "vm-jump-01 runs as mi-jump" in html
    # The only line in that section somebody can act on without opening
    # CloudGuard.
    assert "Cut here" in html


def test_remediation_reports_claims_and_proof_separately():
    html = render_html(report())

    body_html = body(html)
    assert "Tasks marked done in the last 30 days" in body_html
    assert "Findings verified fixed in the last 30 days" in body_html
    # Never summed: one is a statement somebody made, the other is an
    # observation an instrument took.
    assert "Work marked done is a claim; a verified fix is an observation" in body_html


def test_an_empty_attack_path_section_is_not_an_all_clear():
    html = render_html(report(attack_paths=[]))

    normalized = " ".join(html.split())
    assert "not by itself an all-clear" in normalized
    assert "No route was found" in normalized
