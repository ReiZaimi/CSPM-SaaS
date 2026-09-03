"""What leaves the product when somebody asks for the evidence.

An export is the one artefact that outlives the screen it came from. It gets
pasted into an auditor's workbook, mailed to a customer's compliance officer,
and read a year later by somebody who cannot ask what a column meant -- so the
things tested here are the things that go wrong silently: a row that no longer
says which framework it belongs to, a green control whose readings were
summarised into something better than they were, and a title with a comma in it
that quietly becomes two columns.
"""

from app.compliance.export import (
    COLUMNS,
    control_reading_summary,
    export_filename,
    rows,
    to_csv,
)


def control(**overrides) -> dict:
    base = {
        "id": "A.8.9",
        "title": "Configuration management",
        "group": "A.8 Technological controls",
        "technically_assessable": True,
        "status": "PASSING",
        "open_finding_count": 0,
        "rules": [{"rule_id": "AZ-STO-001", "unknown_reasons": []}],
        "readings": [
            {
                "evidence_key": "storage_accounts",
                "outcome": "COMPLETE",
                "scopes": 2,
                "collected_at": "2026-09-03T09:00:00+00:00",
                "retained": True,
            }
        ],
    }
    base.update(overrides)
    return base


def payload(**overrides) -> dict:
    base = {
        "generated_at": "2026-09-03T12:00:00+00:00",
        "organization": "Contoso Ltd",
        "framework": {
            "id": "iso27001",
            "short_name": "ISO 27001",
            "version": "2022",
        },
        "assessment": {
            "scan_id": "11111111-1111-1111-1111-111111111111",
            "completed_at": "2026-09-03T09:05:00+00:00",
            "scan_status": "COMPLETED",
        },
        "controls": [control()],
    }
    base.update(overrides)
    return base


def as_dicts(table: list[list[str]]) -> list[dict]:
    header, *body = table
    return [dict(zip(header, row, strict=True)) for row in body]


# ------------------------------------------------------- provenance per row
def test_every_row_carries_the_framework_and_the_reading_it_came_from() -> None:
    """The thing that happens to every export: fifteen rows are copied into a
    larger sheet. A row that no longer says which framework and which scan it
    came from is a compliance claim with no date on it."""
    row = as_dicts(rows(payload()))[0]

    assert row["framework"] == "ISO 27001"
    assert row["framework_version"] == "2022"
    assert row["assessed_at"] == "2026-09-03T09:05:00+00:00"


def test_an_unassessed_framework_exports_with_no_date_rather_than_todays() -> None:
    """Generating the file is not assessing the estate, and a generated-at date
    in the assessed column would say a scan happened that did not."""
    row = as_dicts(rows(payload(assessment=None)))[0]

    assert row["assessed_at"] == ""


# ----------------------------------------------- the readings behind a control
def test_a_passing_control_exports_the_readings_behind_it() -> None:
    """The half a compliance export usually leaves out. A green row with no
    provenance is a claim; this is what makes it checkable."""
    row = as_dicts(rows(payload()))[0]

    assert row["evidence_keys"] == "storage_accounts"
    assert row["evidence_outcome"] == "COMPLETE"
    assert row["evidence_oldest_read"] == "2026-09-03T09:00:00+00:00"
    assert row["evidence_scopes"] == "2"
    assert row["evidence_retained"] == "yes"


def test_a_key_nothing_read_is_named_as_such() -> None:
    """Not blank, and not "failed". Nothing collected it, which is how a
    control ends up green on nothing."""
    unread = control(
        readings=[
            {
                "evidence_key": "key_vaults",
                "outcome": None,
                "scopes": 0,
                "collected_at": None,
                "retained": False,
            }
        ]
    )
    row = as_dicts(rows(payload(controls=[unread])))[0]

    assert row["evidence_outcome"] == "NOT_READ"
    assert row["evidence_oldest_read"] == ""


def test_the_worst_outcome_and_the_oldest_read_are_what_a_row_reports() -> None:
    summary = control_reading_summary(
        [
            {
                "evidence_key": "a",
                "outcome": "COMPLETE",
                "scopes": 3,
                "collected_at": "2026-09-03T09:00:00+00:00",
                "retained": True,
            },
            {
                "evidence_key": "b",
                "outcome": "PARTIAL",
                "scopes": 1,
                "collected_at": "2026-08-30T09:00:00+00:00",
                "retained": True,
            },
        ]
    )

    assert summary == ("PARTIAL", "2026-08-30T09:00:00+00:00", 4, True)


def test_a_control_with_no_readings_reports_nothing_rather_than_zero() -> None:
    """A control no rule maps to has no readings, and an outcome of COMPLETE
    over an empty list would be the export saying it looked."""
    assert control_reading_summary([]) == ("", "", 0, False)


def test_inconclusive_reasons_travel_with_the_control() -> None:
    """The one verdict a reader cannot act on from the verdict alone. It is
    worth more in an export than on screen: whoever reads the file is usually
    not the person who can see the scan."""
    degraded = control(
        status="INCONCLUSIVE",
        rules=[
            {"rule_id": "AZ-STO-001", "unknown_reasons": ["The scanner role is behind."]},
            {"rule_id": "AZ-STO-002", "unknown_reasons": ["The scanner role is behind."]},
        ],
    )
    row = as_dicts(rows(payload(controls=[degraded])))[0]

    # Distinct: two rules failing for one reason is one sentence.
    assert row["inconclusive_reasons"] == "The scanner role is behind."


# ------------------------------------------------------------- the file itself
def test_a_title_with_a_comma_stays_one_column() -> None:
    """The classic. A control title is prose written by us, and prose has
    commas in it."""
    text = to_csv(payload(controls=[control(title="Backup, restore and recovery")]))

    assert '"Backup, restore and recovery"' in text
    assert len(text.strip().splitlines()) == 2


def test_the_file_opens_as_a_spreadsheet_expects() -> None:
    text = to_csv(payload())

    assert text.startswith(",".join(COLUMNS))
    # CRLF, because Excel wants it.
    assert "\r\n" in text


def test_booleans_are_words_rather_than_true_false() -> None:
    """A spreadsheet coerces TRUE/FALSE into booleans and then formats them in
    the reader's own locale, so a German auditor gets WAHR."""
    row = as_dicts(rows(payload()))[0]

    assert row["technically_assessable"] == "yes"
    assert row["evidence_retained"] == "yes"


def test_the_filename_survives_a_customers_own_name() -> None:
    """An organization is named by its customer, and a name carrying a quote or
    a newline would break the Content-Disposition header it lands in."""
    name = export_filename('Contoso "Global", Ltd\n', "iso27001", "csv")

    assert name == "cloudguard-contoso-global-ltd-iso27001.csv"
    assert '"' not in name and "\n" not in name


def test_an_unnamed_organization_still_produces_a_findable_file() -> None:
    assert export_filename("", "cis-azure", "json") == "cloudguard-organization-cis-azure.json"
