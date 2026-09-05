"""Compliance coverage: catalogue x rules x this organization's latest scan.

The chain, in the order ROADMAP.md sets out:

    reading (evidence) -> rule -> control (requirement) -> framework -> export

This service walks it backwards -- from a framework's controls to the rules
mapped to them, to what those rules found, and to the readings those verdicts
rest on -- and stops there. It produces evidence attributed to a requirement,
never a statement that a requirement is satisfied in law.

**Why the readings are on the control and not only on the finding.** A finding
already cites the readings behind it (``finding_evidence``), which answers "how
do you know this is wrong". The question an auditor actually asks is the other
one: how do you know this control is *met*. A passing control has no findings,
so it had no citations at all -- CloudGuard asserted a green row and offered
nothing to check it against. The readings come from the rules' own declared
evidence keys and the latest scan's ``evidence`` rows, so a passing control now
says which provider calls were made, when, under which permission, and whether
the bytes are still held.

Note where the mappings come from: the ``rules`` table, not the Python
registry. The table is the read-mirror the API already joins findings against,
and a rule removed from the registry keeps its row (disabled) so the controls
it used to answer for do not silently become uncovered.
"""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.compliance.catalog import FRAMEWORKS, Framework, get_framework
from app.compliance.coverage import (
    ControlStatus,
    Reading,
    RuleEvidence,
    coverage_ratio,
    resolve_control_status,
    status_counts,
    summarize_readings,
)
from app.core.enums import FindingStatus, Provider, ScanStatus, TaskOutcome
from app.models.cloud_connection import CloudConnection
from app.models.finding import Finding
from app.models.rule import Rule
from app.models.scan import Evidence, EvidenceBlob, Scan, ScanEvaluationGap, ScanRuleResult

OPEN_STATUSES = [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]


class _Snapshot:
    """Everything the per-control resolution needs, fetched once.

    Assembled up front because a control-by-control query would be ~50 round
    trips per framework, and every control in every framework draws on the same
    three tables.
    """

    def __init__(
        self,
        rules: list[Rule],
        open_findings: dict[str, int],
        rule_results: dict[str, int],
        unknown_reasons: dict[str, tuple[str, ...]],
        has_completed_scan: bool,
        readings: list[tuple[str, str, datetime, list[str], str | None]] | None = None,
        stored_hashes: frozenset[str] = frozenset(),
        scan: Scan | None = None,
    ) -> None:
        self.rules = rules
        self.open_findings = open_findings
        self.rule_results = rule_results
        self.unknown_reasons = unknown_reasons
        self.has_completed_scan = has_completed_scan
        # Every reading the latest scan took, one row per key per scope, and
        # which of their payloads are still held. Fetched once for the whole
        # catalogue: four frameworks over a few hundred controls draw on the
        # same handful of listings.
        self.readings = readings or []
        self.stored_hashes = stored_hashes
        self.scan = scan

    def rules_for(self, framework_id: str, control_id: str) -> list[Rule]:
        return [
            rule
            for rule in self.rules
            if control_id in (rule.compliance_mappings or {}).get(framework_id, [])
        ]

    def readings_for(self, rules: list[Rule]) -> tuple[Reading, ...]:
        """The provider listings these rules' verdicts rest on.

        Taken from what the rules *declare* they read rather than from what the
        scan happened to collect, so a key nothing read still appears -- as a
        reading with no outcome, which is the only honest way to render "this
        control is green and nobody looked".
        """
        keys = {
            key for rule in rules for key in (rule.requires_evidence or []) if key
        }
        if not keys:
            return ()
        return summarize_readings(
            keys,
            [row for row in self.readings if row[0] in keys],
            self.stored_hashes,
        )

    def evidence_for(self, framework_id: str, control_id: str) -> list[RuleEvidence]:
        """Every rule claiming to produce evidence toward this control."""
        matched = self.rules_for(framework_id, control_id)
        return [
            RuleEvidence(
                rule_id=rule.rule_id,
                name=rule.name,
                severity=str(rule.severity),
                open_finding_count=self.open_findings.get(rule.rule_id, 0),
                unknown_count=self.rule_results.get(rule.rule_id, 0),
                evaluated=rule.rule_id in self.rule_results,
                unknown_reasons=self.unknown_reasons.get(rule.rule_id, ()),
            )
            for rule in matched
        ]


async def _snapshot(session: AsyncSession, organization_id: UUID) -> _Snapshot:
    rules = list(
        (await session.execute(select(Rule).where(Rule.enabled.is_(True)))).scalars().all()
    )

    open_rows = (
        await session.execute(
            select(Finding.rule_id, func.count())
            .where(
                Finding.organization_id == organization_id,
                Finding.status.in_(OPEN_STATUSES),
            )
            .group_by(Finding.rule_id)
        )
    ).all()
    open_findings = {rule_id: int(count) for rule_id, count in open_rows}

    last_scan = (
        await session.execute(
            select(Scan)
            .where(
                Scan.organization_id == organization_id,
                Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.PARTIAL]),
            )
            .order_by(Scan.completed_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    # Presence in this dict is "the rule ran"; the value is how often it could
    # not tell. A rule absent from the latest scan is not passing, it is
    # unevaluated -- resolve_control_status treats the two the same way.
    rule_results: dict[str, int] = {}
    if last_scan is not None:
        rows = (
            await session.execute(
                select(ScanRuleResult.rule_id, ScanRuleResult.unknown_count).where(
                    ScanRuleResult.scan_id == last_scan.id
                )
            )
        ).all()
        rule_results = {rule_id: int(unknown) for rule_id, unknown in rows}

    readings, stored = await _readings(session, organization_id, last_scan)

    return _Snapshot(
        rules=rules,
        open_findings=open_findings,
        rule_results=rule_results,
        unknown_reasons=await _unknown_reasons(session, organization_id, last_scan),
        has_completed_scan=last_scan is not None,
        readings=readings,
        stored_hashes=stored,
        scan=last_scan,
    )


async def _readings(
    session: AsyncSession, organization_id: UUID, last_scan: Scan | None
) -> tuple[list[tuple[str, str, datetime, list[str], str | None]], frozenset[str]]:
    """What the latest scan actually read, and which payloads survive.

    Two queries for the whole catalogue rather than one per control. The second
    asks the blob store which hashes are still there rather than inferring it
    from the hash being present: a hash records what was read, and retention
    prunes the bytes on its own schedule, so assuming the payload exists would
    offer an auditor a link that fails.
    """
    if last_scan is None:
        return [], frozenset()

    rows = (
        await session.execute(
            select(
                Evidence.evidence_key,
                Evidence.outcome,
                Evidence.collected_at,
                Evidence.permissions,
                Evidence.content_hash,
            ).where(
                Evidence.organization_id == organization_id,
                Evidence.scan_id == last_scan.id,
            )
        )
    ).all()

    readings = [
        (
            str(key),
            TaskOutcome(outcome).value,
            collected_at,
            list(permissions or []),
            content_hash,
        )
        for key, outcome, collected_at, permissions, content_hash in rows
    ]

    hashes = {content_hash for _k, _o, _c, _p, content_hash in readings if content_hash}
    if not hashes:
        return readings, frozenset()

    stored = (
        (
            await session.execute(
                select(EvidenceBlob.content_hash).where(
                    EvidenceBlob.organization_id == organization_id,
                    EvidenceBlob.content_hash.in_(list(hashes)),
                )
            )
        )
        .scalars()
        .all()
    )
    return readings, frozenset(stored)


# How many distinct explanations to carry per rule. One covers nearly every
# case; the cap exists because a rule can fail differently per resource and a
# control card is not the place for forty sentences. Anything past this is a
# scan-level question, and the collection panel answers it in full.
MAX_REASONS_PER_RULE = 3


async def _unknown_reasons(
    session: AsyncSession, organization_id: UUID, last_scan: Scan | None
) -> dict[str, tuple[str, ...]]:
    """Why each rule could not tell, from the coverage ledger.

    ``scan_evaluation_gaps`` has held these sentences since UNKNOWN became a
    recorded outcome, and the compliance view never read them: a control
    resolved to INCONCLUSIVE and said so, and the reason it was inconclusive
    stayed in the database. That is the one verdict on this page a customer
    cannot act on from the verdict alone, and since the scanner role started
    gaining permissions the answer is often "redeploy the role" -- which is a
    thing they can do this afternoon, if anybody tells them.

    Distinct per rule, because the ledger holds one row per resource and forty
    storage accounts that failed for one reason are one sentence.
    """
    if last_scan is None:
        return {}

    rows = (
        await session.execute(
            select(ScanEvaluationGap.rule_id, ScanEvaluationGap.reason)
            .where(
                ScanEvaluationGap.organization_id == organization_id,
                ScanEvaluationGap.scan_id == last_scan.id,
            )
            .distinct()
        )
    ).all()

    reasons: dict[str, list[str]] = {}
    for rule_id, reason in rows:
        held = reasons.setdefault(rule_id, [])
        if reason and reason not in held and len(held) < MAX_REASONS_PER_RULE:
            held.append(reason)
    return {rule_id: tuple(held) for rule_id, held in reasons.items()}


def _framework_header(framework: Framework) -> dict:
    return {
        "id": framework.id,
        "name": framework.name,
        "short_name": framework.short_name,
        "version": framework.version,
        "authority": framework.authority,
        "url": framework.url,
        "summary": framework.summary,
        "scope_note": framework.scope_note,
    }


def _serialize_reading(reading: Reading, now: datetime) -> dict:
    """One listing, as a control cites it.

    ``age_seconds`` beside the timestamp rather than instead of it: the
    timestamp is what goes in an export and survives being read next year, and
    the age is what a screen needs to say "four hours ago" without every client
    re-deriving it against a clock CloudGuard cannot see.
    """
    return {
        "evidence_key": reading.evidence_key,
        "outcome": reading.outcome,
        "scopes": reading.scopes,
        "collected_at": (
            reading.collected_at.isoformat() if reading.collected_at else None
        ),
        "age_seconds": (
            int((now - _aware(reading.collected_at)).total_seconds())
            if reading.collected_at
            else None
        ),
        "permissions": list(reading.permissions),
        "retained": reading.retained,
    }


def _aware(moment: datetime) -> datetime:
    """PostgreSQL hands back an aware datetime; a fixture may not."""
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _resolve(framework: Framework, snapshot: _Snapshot) -> list[tuple[dict, ControlStatus]]:
    now = datetime.now(UTC)
    resolved: list[tuple[dict, ControlStatus]] = []
    for control in framework.controls:
        evidence = snapshot.evidence_for(framework.id, control.id)
        status = resolve_control_status(evidence, has_completed_scan=snapshot.has_completed_scan)
        readings = snapshot.readings_for(snapshot.rules_for(framework.id, control.id))
        resolved.append(
            (
                {
                    "id": control.id,
                    "title": control.title,
                    "group": control.group,
                    "technically_assessable": control.technically_assessable,
                    "status": status.value,
                    "open_finding_count": sum(e.open_finding_count for e in evidence),
                    # The readings the verdict above rests on. Present for a
                    # passing control too, which is the point: a green row with
                    # nothing behind it is a claim, and this is what turns it
                    # into one somebody can check.
                    "readings": [_serialize_reading(r, now) for r in readings],
                    "rules": [
                        {
                            "rule_id": e.rule_id,
                            "name": e.name,
                            "severity": e.severity,
                            "open_finding_count": e.open_finding_count,
                            "unknown_count": e.unknown_count,
                            "evaluated": e.evaluated,
                            "unknown_reasons": list(e.unknown_reasons),
                        }
                        for e in evidence
                    ],
                },
                status,
            )
        )
    return resolved


async def connected_providers(
    session: AsyncSession, organization_id: UUID
) -> set[Provider]:
    """Which clouds this organization actually has a connection to.

    Every connection, not only the verified ones. A customer part-way through
    connecting AWS should see the AWS benchmark appear as they set it up rather
    than after the first successful scan -- and a framework showing 0% because
    nothing has been scanned yet is an honest zero, unlike one showing 0%
    because the framework is about a cloud they do not use.
    """
    rows = (
        await session.execute(
            select(CloudConnection.provider).where(
                CloudConnection.organization_id == organization_id
            )
        )
    ).scalars()
    return {Provider(value) for value in rows}


def frameworks_for(providers: set[Provider]) -> list[Framework]:
    """The frameworks worth measuring an organization against.

    A framework about one cloud is shown only to organizations that use it.
    An AWS-only tenant measured against CIS Azure would report near-zero
    coverage for reasons that have nothing to do with its security posture,
    which is the same class of misleading number the coverage ledger exists to
    prevent (MULTI_CLOUD.md section 7).

    An organization with no connections yet sees everything. There is nothing
    to scope by, and hiding all the cloud benchmarks from somebody who has not
    connected anything would answer "what does this product check?" with
    silence.
    """
    if not providers:
        return list(FRAMEWORKS)
    return [
        framework
        for framework in FRAMEWORKS
        if framework.provider is None or framework.provider in providers
    ]


async def list_frameworks(session: AsyncSession, organization_id: UUID) -> list[dict]:
    """One summary card per framework this organization's clouds are measured by."""
    snapshot = await _snapshot(session, organization_id)
    providers = await connected_providers(session, organization_id)

    summaries = []
    for framework in frameworks_for(providers):
        resolved = _resolve(framework, snapshot)
        statuses = [status for _, status in resolved]
        summaries.append(
            {
                **_framework_header(framework),
                "control_count": len(statuses),
                "status_counts": status_counts(statuses),
                "coverage_ratio": coverage_ratio(statuses),
                "open_finding_count": sum(c["open_finding_count"] for c, _ in resolved),
            }
        )
    return summaries


async def get_framework_detail(
    session: AsyncSession, organization_id: UUID, framework_id: str
) -> dict | None:
    framework = get_framework(framework_id)
    if framework is None:
        return None

    snapshot = await _snapshot(session, organization_id)
    resolved = _resolve(framework, snapshot)
    statuses = [status for _, status in resolved]

    return {
        **_framework_header(framework),
        "control_count": len(statuses),
        "status_counts": status_counts(statuses),
        "coverage_ratio": coverage_ratio(statuses),
        "open_finding_count": sum(c["open_finding_count"] for c, _ in resolved),
        "assessed": snapshot.has_completed_scan,
        "assessment": _assessment(snapshot),
        "controls": [control for control, _ in resolved],
    }


def _assessment(snapshot: _Snapshot) -> dict | None:
    """Which reading of the estate this assessment is of.

    ``None`` until a scan has completed, which is not the same as an assessment
    with nothing in it: a framework page before the first scan is a catalogue,
    and dating it would put a timestamp on an assessment nobody made.
    """
    scan = snapshot.scan
    if scan is None:
        return None
    return {
        "scan_id": str(scan.id),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        # PARTIAL matters here more than anywhere else on this page. A framework
        # assessed from a scan that could not read part of the estate is an
        # assessment with a hole in it, and an export that did not say so would
        # be the one document where that omission is expensive.
        "scan_status": scan.status.value,
    }


async def build_export(
    session: AsyncSession,
    organization_id: UUID,
    framework_id: str,
    *,
    organization_name: str,
) -> dict | None:
    """The whole assessment as one document, ready to serialize.

    The same numbers the screen shows, plus the two things a screen does not
    need and a document cannot do without: who it is about, and when it was
    generated. Generated on request and never stored, for the reason the reports
    module gives -- a stored assessment outlives the evidence behind it, and
    CloudGuard would then owe an answer about which of five copies is current.
    """
    detail = await get_framework_detail(session, organization_id, framework_id)
    if detail is None:
        return None

    controls = detail.pop("controls")
    assessment = detail.pop("assessment")
    detail.pop("assessed", None)

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "organization": organization_name,
        "framework": detail,
        "assessment": assessment,
        "controls": controls,
    }
