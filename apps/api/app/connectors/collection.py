"""The collection plan, and the executor that runs it.

Collection used to be a fixed sequence of method calls: six ARM categories one
after another, then Graph. That shape carried three problems that are all the
same problem -- nothing declared what a unit of collection *was*, so nothing
could reason about one.

* A category gathered several calls under one ``try``, so one failure discarded
  the sibling data that had already come back. Public IPs failing cost you NSG
  evaluation.
* Ordering encoded dependency. ``logging`` needs storage/SQL/NSG ids, and that
  fact existed only as "call it fifth" -- which also meant everything ran
  sequentially, because nothing knew what was independent.
* A partial result was indistinguishable from a whole one. A listing truncated
  at the page cap flowed into the rules as though it were the environment.

A task declares what it writes, which gap bucket it belongs to, and what it
depends on. The executor derives the rest: what can run at once, what must be
skipped because its input never arrived, and -- the point of the exercise --
which results are trustworthy enough to draw conclusions from.

Provider-neutral on purpose. Azure supplies the tasks (``azure/plan.py``);
nothing here knows what ARM is.

A task may also be scoped to a **region**, which is what AWS needs and Azure
does not: ARM lists a subscription's resources globally, while almost every
``Describe*`` is per region -- so one account reading its security groups in
seventeen regions produces seventeen readings of one evidence key. The executor
therefore identifies a task by key *and* region, and aggregates back to the bare
key whenever the rules ask: a key is trustworthy only if every region's reading
of it was, because "no security group is open" is not a conclusion a view
missing a region can support. Everything above this line still degrades one
``EvidenceKey`` at a time and never learns that regions exist.
"""

import asyncio
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.connectors.evidence import EvidenceCategory, EvidenceKey, ProviderEndpoint
from app.connectors.planning import CollectionPlan
from app.core.enums import TaskOutcome
from app.core.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class CollectionTask:
    """One unit of collection, declared rather than sequenced."""

    # Identifies the task, names what it contributes to the snapshot, and is
    # what a rule declares a dependency on. An ``EvidenceKey`` rather than a
    # string: the two used to have to agree by hand, and a rule naming evidence
    # no task produced simply never degraded.
    key: EvidenceKey
    # Receives everything collected so far, so a dependent task reads its
    # inputs from the run rather than from state shared behind the executor's
    # back. ``diagnostic_settings`` needs the ids the storage and SQL listings
    # produced; this is how it gets them.
    run: Callable[[dict[str, Any]], Awaitable["TaskData"]]
    # Keys that must have produced usable data first.
    depends_on: tuple[EvidenceKey, ...] = ()
    # ARM actions this task needs. Declared here so the permission set, the
    # collector and the rules can be checked against one definition instead of
    # agreeing by hand across three files.
    actions: tuple[str, ...] = ()
    # The provider calls this task makes. Declared beside ``actions`` and for
    # the same reason: the alternative is reading the collector to find out what
    # a stored reading was a reading *of*, months after the fact.
    endpoints: tuple[ProviderEndpoint, ...] = ()
    # Which region this task reads. ``None`` means the listing is global, which
    # is every Azure task and, on AWS, IAM, S3 and Organizations.
    #
    # Deliberately not part of :attr:`key`. A rule depends on evidence and never
    # on a region -- seventeen regional readings of ``security_groups`` are one
    # answer to "did we see the security groups" -- so the region qualifies the
    # task without ever reaching the thing a rule declares.
    region: str | None = None

    @property
    def scoped_key(self) -> str:
        """This task's identity within a run: its key, qualified by region.

        The key stopped being unique the moment a listing became regional, and
        the key is what everything above the connector reads. So the two are
        kept apart rather than merged: this string names one reading, and
        nothing outside this module and the evidence row it becomes ever
        depends on one.
        """
        return f"{self.key.value}@{self.region}" if self.region else self.key.value

    @property
    def category(self) -> EvidenceCategory:
        """Derived from the key, never declared beside it.

        A task used to state both, which meant a task could claim a category
        its key did not belong to -- valid Python, no test, and the only
        symptom a rule that degraded for the wrong reason or not at all.
        """
        return self.key.category


@dataclass
class TaskResult:
    key: EvidenceKey
    category: EvidenceCategory
    outcome: TaskOutcome
    detail: str = ""
    item_count: int = 0
    # The provider actions the read was made under, copied from the task's own
    # declaration. Recorded rather than looked up later because a role can be
    # redeployed between the scan and the question: what matters is what the
    # read actually needed at the moment it was made.
    permissions: tuple[str, ...] = ()
    # Which provider calls produced it, copied from the task's declaration for
    # the same reason ``permissions`` is: the answer must describe the read that
    # was made, not the collector as it stands whenever somebody asks.
    endpoints: tuple[ProviderEndpoint, ...] = ()
    # Set only on a reading this run did not make: when the provider was
    # actually read, on the earlier scan the plan carried this forward from.
    # Absent means the obvious thing -- this run read it, just now.
    carried_from: datetime | None = None
    # Which region this was a reading of; ``None`` for a global listing.
    region: str | None = None

    @property
    def is_trustworthy(self) -> bool:
        return self.outcome.is_trustworthy

    @property
    def scoped_key(self) -> str:
        """Matches :attr:`CollectionTask.scoped_key`, and for the same reason."""
        return f"{self.key.value}@{self.region}" if self.region else self.key.value


@dataclass
class CoverageReport:
    """What the run actually managed to see.

    Travels with the snapshot rather than being logged, because the rule engine
    is the only thing that can act on it -- and acting on it means the
    difference between UNKNOWN and a PASS nobody earned.
    """

    results: dict[str, TaskResult] = field(default_factory=dict)
    # What each task produced, kept apart rather than only merged.
    #
    # The merged dict the executor fills is what the normalizer reads, and it
    # is all a scan needed while evidence was one blob per subscription. Storing
    # evidence per unit needs the units, and they are the same objects -- held
    # by reference here, not copied -- so keeping them costs nothing and is the
    # difference between an unchanged listing being stored once or once per
    # scan for ever.
    #
    # Deliberately absent from :meth:`to_json`: that serializes the *coverage*,
    # which travels inside the snapshot, and putting the payloads there would
    # write every listing into the snapshot a second time.
    payloads: dict[str, dict[str, Any]] = field(default_factory=dict)

    def record(self, result: TaskResult, payload: dict[str, Any] | None = None) -> None:
        self.results[result.scoped_key] = result
        if payload:
            self.payloads[result.scoped_key] = payload

    @property
    def is_complete(self) -> bool:
        return all(r.is_trustworthy for r in self.results.values())

    def untrustworthy(self) -> list[TaskResult]:
        return [r for r in self.results.values() if not r.is_trustworthy]

    def readings_of(self, key: EvidenceKey) -> list[TaskResult]:
        """Every reading of one evidence key, however many regions produced it."""
        return [r for r in self.results.values() if r.key == key]

    def saw(self, key: EvidenceKey) -> bool:
        """Whether this run produced any reading of a key at all."""
        return any(r.key == key for r in self.results.values())

    def key_is_trustworthy(self, key: EvidenceKey) -> bool:
        """Whether *every* reading of a key can be relied on.

        Every, not any, and that is the whole reason the aggregation exists. A
        listing that failed in one region of seventeen has produced a partial
        view of the estate, and a rule concluding "nothing is open" from it
        would be answering a question it does not have the evidence for -- the
        same reason a truncated listing is PARTIAL rather than COMPLETE.

        False for a key nothing read, which is the honest answer to "can this
        be relied on" when there is nothing to rely on.
        """
        readings = self.readings_of(key)
        return bool(readings) and all(r.is_trustworthy for r in readings)

    def key_problems(self) -> dict[str, str]:
        """Evidence key -> why that one piece of evidence cannot be relied on.

        What the rules degrade on, and finer than the category view below on
        purpose. A subscription whose PostgreSQL listing failed has read its SQL
        servers perfectly well, and the SQL rule going UNKNOWN over a sibling
        listing is a gap CloudGuard invented rather than one it found.

        PARTIAL lands here alongside FAILED deliberately: a truncated listing is
        treated exactly as an unreachable API, because "none of them are public"
        is not a conclusion a list missing an unknown number of entries can
        support.
        """
        problems: dict[str, list[str]] = {}
        for result in self.results.values():
            if result.is_trustworthy:
                continue
            reason = result.detail or result.outcome.value.lower()
            # Keyed by the bare key, because that is what a rule declares. A
            # region names itself inside the reason instead: the rule loses its
            # verdict either way, and whoever reads the gap still learns that
            # sixteen regions were fine and one was not.
            problems.setdefault(result.key.value, []).append(
                f"{result.region}: {reason}" if result.region else reason
            )
        return {key: "; ".join(reasons) for key, reasons in problems.items()}

    def category_problems(self) -> dict[str, str]:
        """Category -> why its data cannot be relied on.

        The customer-facing view, and a different question from
        :meth:`key_problems` rather than a coarser copy of it. This is what the
        scan banner shows and what a stale role deployment explains, both of
        which are about a *permission* -- and permissions are granted per
        category, never per listing.
        """
        problems: dict[str, list[str]] = {}
        for result in self.results.values():
            if result.is_trustworthy:
                continue
            problems.setdefault(result.category.value, []).append(
                f"{result.scoped_key}: {result.detail or result.outcome.value.lower()}"
            )
        return {category: "; ".join(reasons) for category, reasons in problems.items()}

    def to_json(self) -> dict[str, Any]:
        entries: dict[str, Any] = {}
        for key, r in self.results.items():
            entry: dict[str, Any] = {
                # The bare evidence key, stated rather than recoverable by
                # splitting the entry name. A regional reading is filed under
                # ``security_groups@eu-west-1`` so that seventeen of them do
                # not overwrite each other, and everything reading a stored
                # capture wants the key it was a reading *of* -- deriving that
                # from the name would make the record a function of how the
                # name happens to be spelled.
                "key": r.key.value,
                "region": r.region,
                "category": r.category.value,
                "outcome": r.outcome.value,
                "detail": r.detail,
                "item_count": r.item_count,
                "permissions": list(r.permissions),
                # What was actually called, and under which contract. Two
                # answers a stored capture could not previously give: an absent
                # field is a setting nobody set *or* an api-version too old to
                # return it, and only the second is CloudGuard's fault.
                "endpoints": [
                    {"path": e.path, "api_version": e.api_version}
                    for e in r.endpoints
                ],
            }
            # Written only where it applies, so a capture taken entirely by
            # this run looks exactly as it always did. It is provenance for
            # whoever reads the stored snapshot later: without it a carried
            # reading inside a capture is indistinguishable from one taken at
            # the moment the capture was written.
            if r.carried_from is not None:
                entry["carried_from"] = r.carried_from.isoformat()
            entries[key] = entry
        return entries


@dataclass
class TaskData:
    """A task's output, and whether it is all of it.

    Returning the incompleteness alongside the data is the only way a caller
    can tell the two apart. A list is a list; nothing about the shape of one
    says whether it stopped early.
    """

    data: dict[str, Any]
    partial_reason: str | None = None


class CollectionRun:
    """Executes a plan: dependency-ordered, concurrent within each wave."""

    def __init__(
        self,
        tasks: list[CollectionTask],
        *,
        on_progress: Callable[[int, int], Awaitable[None]] | None = None,
        plan: CollectionPlan | None = None,
        max_concurrency: int | None = None,
    ) -> None:
        # The plan is applied to what the provider offers, never the other way
        # round: a plan naming a key this provider does not produce asks for
        # nothing rather than inventing a task.
        self.plan = plan.restrict(t.key for t in tasks) if plan is not None else None
        self.carried = dict(self.plan.carried) if self.plan is not None else {}
        self.tasks = self._select(tasks)
        self.on_progress = on_progress
        self._by_scope = {t.scoped_key: t for t in self.tasks}
        # Which evidence this run produces, without regard to how many regions
        # produce it. Dependencies are declared against this, never against
        # ``_by_scope``: a task needing the instance listing needs all of it.
        self._produces = {t.key for t in self.tasks}
        # How many tasks may be in flight at once. Unbounded was fine while a
        # wave was eleven ARM listings; a regional fan-out puts a listing per
        # region in one wave, and a customer with seventeen regions would open
        # a hundred and fifty concurrent calls and be throttled for it. A
        # provider that says nothing keeps the old behaviour exactly.
        self._gate = asyncio.Semaphore(max_concurrency or len(self.tasks) or 1)
        self._validate()

    def _select(self, tasks: list[CollectionTask]) -> list[CollectionTask]:
        """The tasks this run will actually execute.

        Without a plan, all of them -- the shape every scan had before planning
        existed, and still the shape of a scan with nothing to carry forward.

        With one, the plan's keys *and whatever those keys need*. A plan is
        written against what the rules and the product ask for, and asking for
        diagnostic settings is asking for the storage and SQL listings whose ids
        they are read from, whether or not anything else wanted those. The
        planner does not know that -- dependencies are declared by the provider,
        on the tasks, which is where they belong -- so the closure is taken here
        rather than refused here. The alternative is a scan that raises on a
        plan nobody could tell was incomplete.
        """
        if self.plan is None:
            return list(tasks)

        by_key = {t.key: t for t in tasks}
        wanted = {t.key for t in tasks if self.plan.wants(t.key)}
        frontier = list(wanted)
        while frontier:
            task = by_key.get(frontier.pop())
            if task is None:
                continue
            for dependency in task.depends_on:
                if dependency in wanted or dependency in self.carried:
                    continue
                wanted.add(dependency)
                frontier.append(dependency)
        return [t for t in tasks if t.key in wanted]

    def _validate(self) -> None:
        """A plan that cannot run should say so before it starts running.

        Both failures here are typos with expensive symptoms: a dependency on a
        key nothing produces silently skips a task forever, and a cycle hangs
        the wave loop with no output to explain it.
        """
        counts = Counter(t.scoped_key for t in self.tasks)
        duplicates = sorted(key for key, n in counts.items() if n > 1)
        if duplicates:
            raise ValueError(
                f"Duplicate collection task keys: {', '.join(duplicates)}"
            )

        for task in self.tasks:
            for dependency in task.depends_on:
                # Carried counts: the payload is seeded before the first wave,
                # so a task reading it has its input. Anything else here is the
                # original typo -- a dependency the provider never produces --
                # since a plan that omits a dependency has already had it added
                # back by :meth:`_select`.
                if dependency in self._produces or dependency in self.carried:
                    continue
                raise ValueError(
                    f"Task {task.key!r} depends on {dependency!r}, which no task produces"
                )

    def waves(self) -> list[list[CollectionTask]]:
        """Tasks grouped so everything in a wave can run at once."""
        remaining = dict(self._by_scope)
        # A carried reading satisfies a dependency exactly as a fresh one does:
        # its payload is seeded into the run's data before the first wave, so a
        # task reading it cannot tell the difference and has no business being
        # able to.
        satisfied: set[str] = set(self.carried)
        # How many readings of each key are still unscheduled. Counting down
        # rather than marking satisfied on the first one is the difference
        # between a dependent task seeing one region and seeing the estate.
        pending = Counter(t.key for t in self.tasks)
        waves: list[list[CollectionTask]] = []

        while remaining:
            ready = [
                t for t in remaining.values() if all(d in satisfied for d in t.depends_on)
            ]
            if not ready:
                raise ValueError(
                    "Collection plan has a dependency cycle among: "
                    + ", ".join(sorted(remaining))
                )
            waves.append(ready)
            for task in ready:
                del remaining[task.scoped_key]
                pending[task.key] -= 1
                if pending[task.key] == 0:
                    satisfied.add(task.key)
        return waves

    @property
    def size(self) -> int:
        """Known before execution, which is what lets collection report progress."""
        return len(self.tasks)

    async def execute(self, data: dict[str, Any]) -> CoverageReport:
        """Run every task, merging output into ``data``.

        No task failure ends the run. That is the same position
        ``_collect_category`` took and it remains right: one unreachable API
        must cost the checks that needed it and nothing else.
        """
        report = CoverageReport()
        done = 0
        self._seed_carried(report, data)

        for wave in self.waves():
            runnable, skipped = self._partition(wave, report)

            for task in skipped:
                blocker = next(
                    d for d in task.depends_on if not report.key_is_trustworthy(d)
                )
                report.record(
                    TaskResult(
                        key=task.key,
                        category=task.category,
                        region=task.region,
                        permissions=task.actions,
                        endpoints=task.endpoints,
                        outcome=TaskOutcome.SKIPPED,
                        detail=f"needs {blocker}, which did not produce usable data",
                    )
                )
                done += 1

            results = await asyncio.gather(
                *(self._run_one(task, data) for task in runnable),
                return_exceptions=False,
            )
            for task, result, produced in results:
                self._merge(data, task, produced)
                report.record(result, produced)
                done += 1

            if self.on_progress:
                await self.on_progress(done, self.size)

        return report

    def _seed_carried(self, report: CoverageReport, data: dict[str, Any]) -> None:
        """Put the readings this run is not making into the capture.

        A carried reading enters the run as data and as coverage both, because
        the capture has to be whole: replay reads the snapshot, the normalizer
        reads the merged data, and a hole where a task used to be would read as
        evidence that never arrived rather than evidence already held.

        Recorded COMPLETE, which is what it was. Age is not incompleteness --
        the reading is exactly what the provider said, and ``carried_from``
        says when it said it. Degrading it to PARTIAL would tell every rule
        that reads it to return UNKNOWN, which is how a cost optimization turns
        into a product that knows less than it did.
        """
        for key, reading in self.carried.items():
            data.update(reading.payload)
            report.record(
                TaskResult(
                    key=key,
                    category=key.category,
                    outcome=TaskOutcome.COMPLETE,
                    detail="carried forward from an earlier scan",
                    item_count=reading.item_count,
                    permissions=reading.permissions,
                    endpoints=reading.endpoints,
                    carried_from=reading.collected_at,
                ),
                reading.payload,
            )

    def _partition(
        self, wave: list[CollectionTask], report: CoverageReport
    ) -> tuple[list[CollectionTask], list[CollectionTask]]:
        """Split a wave into what can run and what its inputs have ruled out."""
        runnable: list[CollectionTask] = []
        skipped: list[CollectionTask] = []
        for task in wave:
            blocked = any(
                report.saw(d) and not report.key_is_trustworthy(d)
                for d in task.depends_on
            )
            (skipped if blocked else runnable).append(task)
        return runnable, skipped

    @staticmethod
    def _merge(
        data: dict[str, Any], task: CollectionTask, produced: dict[str, Any]
    ) -> None:
        """Fold one task's output into the capture.

        A global listing is the whole answer for its key, and replaces it. A
        regional one is a seventeenth of the answer, so it appends a block
        naming the region it came from, with the provider's payload untouched
        inside ``items`` -- the capture is stored verbatim, and a scan replayed
        years from now has to read what the provider actually said.

        Blocks rather than one flattened list, because the region is a fact
        about a reading that most listings do not repeat inside themselves. A
        normalizer forced to recover it from an ARN would recover nothing for
        the services whose ARNs omit the region, and would then have to guess.
        """
        if task.region is None:
            data.update(produced)
            return
        for key, value in produced.items():
            block = {"region": task.region, "items": value}
            existing = data.get(key)
            if isinstance(existing, list):
                existing.append(block)
            else:
                data[key] = [block]

    async def _run_one(
        self, task: CollectionTask, collected: dict[str, Any]
    ) -> tuple[CollectionTask, TaskResult, dict[str, Any]]:
        """Run one task, converting any failure into a recorded gap.

        The bare ``except`` is the design, not an oversight: every failure must
        leave a trace the rule engine can see, and no single API may take down
        a scan.

        The task comes back out with its result because the caller merges the
        payload and needs to know whether it was a region's worth or all of it.
        """
        def outcome(
            result: TaskOutcome, detail: str = "", item_count: int = 0
        ) -> TaskResult:
            return TaskResult(
                key=task.key,
                category=task.category,
                region=task.region,
                permissions=task.actions,
                endpoints=task.endpoints,
                outcome=result,
                detail=detail,
                item_count=item_count,
            )

        async with self._gate:
            try:
                produced = await task.run(collected)
            except Exception as exc:
                message = str(exc) or type(exc).__name__
                log.warning(
                    "collection.task_failed", task=task.scoped_key, error=message
                )
                return task, outcome(TaskOutcome.FAILED, message), {}

        if isinstance(produced, TaskData):
            payload, partial_reason = produced.data, produced.partial_reason
        else:  # a task that cannot be partial returns a plain dict
            payload, partial_reason = produced, None

        count = sum(len(v) for v in payload.values() if isinstance(v, list | dict))
        if partial_reason:
            log.warning(
                "collection.task_partial", task=task.scoped_key, reason=partial_reason
            )
            return task, outcome(TaskOutcome.PARTIAL, partial_reason, count), payload

        return task, outcome(TaskOutcome.COMPLETE, item_count=count), payload
