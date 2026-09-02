"""What is worth telling somebody, and what is not.

Most of these are about restraint. A CSPM that notifies per finding becomes a
filter rule in the second week, so the interesting assertions are the ones about
what the sweep declines to say -- a real finding on an unreachable asset, a
status a person moved by hand, the same failing listing on every scan.

The judgement lives in ``_reachable_findings`` and friends; these hold it in
place, because every one of them is the kind of rule that gets relaxed by
accident and only shows up as a bell nobody looks at any more.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.core.enums import FindingEvent, NotificationKind, TaskOutcome
from app.models.finding import Finding
from app.models.history import FindingEventRecord
from app.models.resource import ResourceRecord
from app.models.scan import Evidence
from app.services import notifications as service

NOW = datetime.now(UTC)
ORG = uuid.uuid4()


class Result:
    def __init__(self, rows: list) -> None:
        self._rows = rows
        self.rowcount = 1

    def scalars(self):
        return self

    def all(self) -> list:
        return self._rows

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class FakeSession:
    """Answers each query by what it selects from, records what is inserted."""

    def __init__(
        self,
        *,
        detections: list | None = None,
        resolutions: list | None = None,
        evidence: list | None = None,
        watermark: datetime | None = None,
    ) -> None:
        # Two queries read finding_events and they select different shapes --
        # detections join the asset, resolutions do not. Kept apart here rather
        # than answered with one list, or the fake hands three-tuples to the
        # branch expecting two and fails somewhere that is not the point.
        self.detections = detections or []
        self.resolutions = resolutions or []
        self.evidence = evidence or []
        self.watermark = watermark
        self.written: list[dict] = []
        self.statements: list[str] = []

    async def execute(self, statement: object):
        text = str(statement)
        self.statements.append(text)
        if text.lstrip().upper().startswith("INSERT INTO NOTIFICATIONS"):
            params = statement.compile().params  # type: ignore[attr-defined]
            self.written.append(params)
            return Result([])
        if "FROM notifications" in text:
            return Result([self.watermark] if self.watermark else [])
        if "FROM finding_events" in text:
            joins_the_asset = "cloud_resources" in text
            return Result(self.detections if joins_the_asset else self.resolutions)
        if "FROM evidence" in text:
            return Result(self.evidence)
        return Result([])

    def kinds(self) -> list[str]:
        return [str(row["kind"]) for row in self.written]


class FakeGraph:
    """A graph where named assets stand on a route and everything else does not."""

    def __init__(self, reachable: set[str]) -> None:
        self._reachable = reachable

    def paths_through(self, resource_id: str) -> list:
        return ["a route"] if resource_id in self._reachable else []


def a_finding(title: str = "Storage account allows public blob access") -> Finding:
    finding = Finding(
        organization_id=ORG, rule_id="AZ-STO-001", title=title, status="OPEN"  # type: ignore[arg-type]
    )
    finding.id = uuid.uuid4()
    return finding


def an_event(
    finding: Finding,
    event: FindingEvent,
    *,
    scan_id: uuid.UUID | None = None,
    observed_at: datetime | None = None,
) -> FindingEventRecord:
    return FindingEventRecord(
        organization_id=ORG,
        finding_id=finding.id,
        event=event,
        current_status="OPEN",  # type: ignore[arg-type]
        scan_id=scan_id,
        observed_at=observed_at or NOW,
    )


def an_asset(name: str, resource_id: str) -> ResourceRecord:
    record = ResourceRecord(
        organization_id=ORG, name=name, provider_resource_id=resource_id
    )
    record.id = uuid.uuid4()
    return record


def a_reading(key: str, outcome: TaskOutcome, detail: str | None = None) -> Evidence:
    return Evidence(
        organization_id=ORG,
        scan_id=uuid.uuid4(),
        evidence_key=key,
        category="storage",
        outcome=outcome,
        detail=detail,
        collected_at=NOW,
    )


@pytest.fixture
def reachable(monkeypatch):
    """Point the sweep at a graph this test controls."""

    def _install(ids: set[str]) -> None:
        async def load_graph(_session, _org):
            return FakeGraph(ids)

        monkeypatch.setattr(service.graph_service, "load_graph", load_graph)

    return _install


# --------------------------------------------------------------- restraint
async def test_a_finding_on_an_unreachable_asset_is_not_news(reachable) -> None:
    """The judgement the whole feature rests on.

    Real, and not news. Severity is the rulebook's opinion; whether an attacker
    can walk to the thing is the product's. A bell that fired on every finding
    would be a filter rule inside a fortnight.
    """
    reachable(set())
    finding = a_finding()
    session = FakeSession(
        detections=[
            (
                an_event(finding, FindingEvent.DETECTED),
                finding,
                an_asset("sandbox", "/vm/sandbox"),
            )
        ]
    )

    written = await service.derive(session, ORG)  # type: ignore[arg-type]

    assert written == 0
    assert session.written == []


async def test_a_finding_on_a_reachable_asset_is(reachable) -> None:
    reachable({"/storage/prod"})
    finding = a_finding()
    session = FakeSession(
        detections=[
            (
                an_event(finding, FindingEvent.DETECTED),
                finding,
                an_asset("prodstore", "/storage/prod"),
            )
        ]
    )

    written = await service.derive(session, ORG)  # type: ignore[arg-type]

    assert written == 1
    row = session.written[0]
    assert row["kind"] is NotificationKind.REACHABLE_FINDING
    assert "prodstore" in row["title"]
    assert row["link"] == f"/findings/{finding.id}"
    # Says why this one and not the others, so the bell reads as a judgement
    # rather than as a sample.
    assert "route" in (row["detail"] or "")


async def test_a_status_a_person_moved_is_not_a_verified_fix(reachable) -> None:
    """Marking work done is a claim; a scan returning PASS is the evidence.

    A RESOLVED event with no scan behind it is somebody moving the workflow by
    hand, and announcing it as a verified fix would be the product
    congratulating a customer on their own assertion.

    Asserted against the query rather than against a row, because this filter
    lives in SQL: a fake that returned the row anyway would prove the opposite
    of what it looks like it proves. Brittle on purpose -- the alternative is a
    test that passes whether or not the condition is there.
    """
    reachable(set())
    session = FakeSession()

    await service.derive(session, ORG)  # type: ignore[arg-type]

    resolutions = [
        text
        for text in session.statements
        if "FROM finding_events" in text and "cloud_resources" not in text
    ]
    assert resolutions, "the verified-fix query never ran"
    assert "scan_id IS NOT NULL" in resolutions[0]


async def test_a_verified_fix_is_reported_wherever_it_happened(reachable) -> None:
    """No reachability bar on good news.

    The bar exists to keep bad news proportionate. Applying it to a fix would
    report a narrower story than the true one -- and the north-star metric is
    verified risk reduction, so this is the notification the product most wants
    to be able to send.
    """
    reachable(set())
    finding = a_finding("Public RDP")
    session = FakeSession(
        resolutions=[
            (an_event(finding, FindingEvent.RESOLVED, scan_id=uuid.uuid4()), finding)
        ]
    )

    written = await service.derive(session, ORG)  # type: ignore[arg-type]

    assert written == 1
    assert session.written[0]["kind"] is NotificationKind.VERIFIED_FIX
    assert session.written[0]["title"].startswith("Fixed:")


# ---------------------------------------------------------------- coverage
async def test_a_failed_reading_is_news(reachable) -> None:
    """The notification most products do not send.

    A listing that fails degrades its rules to UNKNOWN rather than to PASS, so
    the score holds steady while the evidence under it thins out. Silence would
    let an unchanged number read as an unchanged estate.
    """
    reachable(set())
    session = FakeSession(evidence=[a_reading("storage_accounts", TaskOutcome.FAILED)])

    written = await service.derive(session, ORG)  # type: ignore[arg-type]

    assert written == 1
    row = session.written[0]
    assert row["kind"] is NotificationKind.COVERAGE_DROP
    assert row["subject_id"] == "storage_accounts"


async def test_a_partial_reading_is_news_too(reachable) -> None:
    """PARTIAL is not a lesser failure.

    A listing missing an unknown number of entries cannot support "none of them
    are public", which is the same as not having read it.
    """
    reachable(set())
    session = FakeSession(evidence=[a_reading("virtual_machines", TaskOutcome.PARTIAL)])

    await service.derive(session, ORG)  # type: ignore[arg-type]

    assert session.written[0]["kind"] is NotificationKind.COVERAGE_DROP
    assert "part of" in session.written[0]["title"]


async def test_a_coverage_drop_is_keyed_on_the_listing_not_the_row(reachable) -> None:
    """So a listing failing on every scan is announced once, not hourly.

    The subject is the evidence key, so the unique index refuses the second and
    later attempts. It becomes news again only when it recovers and fails
    afresh.
    """
    reachable(set())
    session = FakeSession(
        evidence=[
            a_reading("storage_accounts", TaskOutcome.FAILED),
            a_reading("storage_accounts", TaskOutcome.FAILED),
        ]
    )

    await service.derive(session, ORG)  # type: ignore[arg-type]

    assert {row["subject_id"] for row in session.written} == {"storage_accounts"}


# --------------------------------------------------------------- cold start
async def test_a_new_organization_is_not_handed_its_whole_history(reachable) -> None:
    """A customer onboarding today should not receive a month of news.

    With no notifications yet there is no watermark, so the sweep bounds itself.
    Without the bound, the day this ships every existing tenant gets one
    enormous batch of things they have already dealt with.
    """
    reachable(set())
    session = FakeSession()

    since = await service._watermark(session, ORG)  # type: ignore[arg-type]

    assert since > datetime.now(UTC) - service.COLD_START - timedelta(minutes=1)


async def test_the_watermark_is_the_newest_thing_already_said(reachable) -> None:
    reachable(set())
    yesterday = NOW - timedelta(days=1)
    session = FakeSession(watermark=yesterday)

    assert await service._watermark(session, ORG) == yesterday  # type: ignore[arg-type]
