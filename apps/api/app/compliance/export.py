"""A framework's assessment as a file somebody can take away.

The last link in the chain this module set exists to make followable: a reading
supports a rule, a rule answers a control, controls make up a framework -- and
an auditor asks for that as a document, not as a screen. Two formats, because
the two readers are different: CSV is what goes into the spreadsheet an audit
is actually run from, and JSON is what a GRC platform ingests without anybody
retyping it.

**Every row carries its own provenance.** The framework, its version and when
the assessment was read are repeated on each line rather than written once in a
header block. A header would be tidier and would not survive the thing that
happens to every export -- somebody copies fifteen rows into a larger sheet,
where a row that no longer says which reading it came from is a compliance
claim with no date on it.

Pure functions. Nothing here touches the database or the request, so what an
export contains is testable without a scan.
"""

import csv
import io
from typing import Any

# The worst outcome wins, and "nothing read this" is worse than a failed read
# for a control that is otherwise green: a failure is at least recorded as one.
_OUTCOME_RANK = {"FAILED": 3, "PARTIAL": 2, "COMPLETE": 1}

NOT_READ = "NOT_READ"

COLUMNS = (
    "framework",
    "framework_version",
    "assessed_at",
    "control_id",
    "control_group",
    "control_title",
    "status",
    "technically_assessable",
    "open_findings",
    "rules",
    "evidence_keys",
    "evidence_outcome",
    "evidence_oldest_read",
    "evidence_scopes",
    "evidence_retained",
    "inconclusive_reasons",
)


def control_reading_summary(readings: list[dict]) -> tuple[str, str, int, bool]:
    """One line's worth of provenance from a control's readings.

    Returns the worst outcome, the oldest read, how many scopes were covered,
    and whether every payload behind them is still stored. Worst and oldest for
    the same reason the per-key aggregation takes them: a control is only as
    good as the least current, least complete thing it rests on, and any other
    choice lets forty-nine good subscriptions hide the one that failed.
    """
    if not readings:
        return "", "", 0, False

    outcomes = [reading.get("outcome") or NOT_READ for reading in readings]
    worst = max(outcomes, key=lambda outcome: _OUTCOME_RANK.get(outcome, 4))
    timestamps = sorted(
        str(reading["collected_at"]) for reading in readings if reading.get("collected_at")
    )
    scopes = sum(int(reading.get("scopes") or 0) for reading in readings)
    retained = bool(readings) and all(bool(r.get("retained")) for r in readings)
    return worst, (timestamps[0] if timestamps else ""), scopes, retained


def rows(payload: dict[str, Any]) -> list[list[str]]:
    """The export as a table, header first."""
    framework = payload["framework"]
    assessed_at = (payload.get("assessment") or {}).get("completed_at") or ""

    table: list[list[str]] = [list(COLUMNS)]
    for control in payload["controls"]:
        readings = control.get("readings") or []
        outcome, oldest, scopes, retained = control_reading_summary(readings)
        reasons = sorted(
            {
                reason
                for rule in control.get("rules") or []
                for reason in rule.get("unknown_reasons") or []
            }
        )
        table.append(
            [
                framework["short_name"],
                framework["version"],
                str(assessed_at),
                control["id"],
                control["group"],
                control["title"],
                control["status"],
                _yes_no(control["technically_assessable"]),
                str(control["open_finding_count"]),
                # Semicolons rather than commas inside a cell: a comma is what
                # the file is delimited by, and a reader opening this in a
                # spreadsheet that guesses badly should still see one column.
                "; ".join(rule["rule_id"] for rule in control.get("rules") or []),
                "; ".join(reading["evidence_key"] for reading in readings),
                outcome,
                oldest,
                str(scopes),
                _yes_no(retained) if readings else "",
                "; ".join(reasons),
            ]
        )
    return table


def to_csv(payload: dict[str, Any]) -> str:
    """RFC 4180 quoting, and CRLF line endings, because Excel wants both."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerows(rows(payload))
    return buffer.getvalue()


def _yes_no(value: bool) -> str:
    """Written out rather than TRUE/FALSE. A spreadsheet coerces the second into
    a boolean and then formats it in the reader's own locale."""
    return "yes" if value else "no"


def export_filename(organization: str, framework_id: str, extension: str) -> str:
    """A filename somebody can find again in a downloads folder.

    Slugged rather than passed through: an organization is named by its
    customer, and a name carrying a quote or a newline would break the
    ``Content-Disposition`` header it lands in.
    """
    slug = "".join(char if char.isalnum() else "-" for char in organization.lower())
    slug = "-".join(part for part in slug.split("-") if part) or "organization"
    return f"cloudguard-{slug}-{framework_id}.{extension}"
