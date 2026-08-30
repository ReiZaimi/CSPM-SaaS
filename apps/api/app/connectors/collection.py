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
"""

import asyncio
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from app.connectors.evidence import EvidenceCategory, EvidenceKey
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

    @property
    def is_trustworthy(self) -> bool:
        return self.outcome.is_trustworthy


@dataclass
class CoverageReport:
    """What the run actually managed to see.

    Travels with the snapshot rather than being logged, because the rule engine
    is the only thing that can act on it -- and acting on it means the
    difference between UNKNOWN and a PASS nobody earned.
    """

    results: dict[str, TaskResult] = field(default_factory=dict)

    def record(self, result: TaskResult) -> None:
        self.results[result.key] = result

    @property
    def is_complete(self) -> bool:
        return all(r.is_trustworthy for r in self.results.values())

    def untrustworthy(self) -> list[TaskResult]:
        return [r for r in self.results.values() if not r.is_trustworthy]

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
        return {
            result.key.value: result.detail or result.outcome.value.lower()
            for result in self.results.values()
            if not result.is_trustworthy
        }

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
                f"{result.key.value}: {result.detail or result.outcome.value.lower()}"
            )
        return {category: "; ".join(reasons) for category, reasons in problems.items()}

    def to_json(self) -> dict[str, Any]:
        return {
            key: {
                "category": r.category.value,
                "outcome": r.outcome.value,
                "detail": r.detail,
                "item_count": r.item_count,
            }
            for key, r in self.results.items()
        }


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
    ) -> None:
        self.tasks = tasks
        self.on_progress = on_progress
        self._by_key = {t.key: t for t in tasks}
        self._validate()

    def _validate(self) -> None:
        """A plan that cannot run should say so before it starts running.

        Both failures here are typos with expensive symptoms: a dependency on a
        key nothing produces silently skips a task forever, and a cycle hangs
        the wave loop with no output to explain it.
        """
        counts = Counter(t.key for t in self.tasks)
        duplicates = sorted(key for key, n in counts.items() if n > 1)
        if duplicates:
            raise ValueError(
                f"Duplicate collection task keys: {', '.join(duplicates)}"
            )

        for task in self.tasks:
            for dependency in task.depends_on:
                if dependency not in self._by_key:
                    raise ValueError(
                        f"Task {task.key!r} depends on {dependency!r}, which no task produces"
                    )

    def waves(self) -> list[list[CollectionTask]]:
        """Tasks grouped so everything in a wave can run at once."""
        remaining = dict(self._by_key)
        satisfied: set[str] = set()
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
                del remaining[task.key]
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

        for wave in self.waves():
            runnable, skipped = self._partition(wave, report)

            for task in skipped:
                blocker = next(
                    d for d in task.depends_on if not report.results[d].is_trustworthy
                )
                report.record(
                    TaskResult(
                        key=task.key,
                        category=task.category,
                        outcome=TaskOutcome.SKIPPED,
                        detail=f"needs {blocker}, which did not produce usable data",
                    )
                )
                done += 1

            results = await asyncio.gather(
                *(self._run_one(task, data) for task in runnable),
                return_exceptions=False,
            )
            for result, produced in results:
                data.update(produced)
                report.record(result)
                done += 1

            if self.on_progress:
                await self.on_progress(done, self.size)

        return report

    def _partition(
        self, wave: list[CollectionTask], report: CoverageReport
    ) -> tuple[list[CollectionTask], list[CollectionTask]]:
        """Split a wave into what can run and what its inputs have ruled out."""
        runnable: list[CollectionTask] = []
        skipped: list[CollectionTask] = []
        for task in wave:
            blocked = any(
                d in report.results and not report.results[d].is_trustworthy
                for d in task.depends_on
            )
            (skipped if blocked else runnable).append(task)
        return runnable, skipped

    async def _run_one(
        self, task: CollectionTask, collected: dict[str, Any]
    ) -> tuple[TaskResult, dict[str, Any]]:
        """Run one task, converting any failure into a recorded gap.

        The bare ``except`` is the design, not an oversight: every failure must
        leave a trace the rule engine can see, and no single API may take down
        a scan.
        """
        try:
            produced = await task.run(collected)
        except Exception as exc:
            message = str(exc) or type(exc).__name__
            log.warning("collection.task_failed", task=task.key, error=message)
            return (
                TaskResult(
                    key=task.key,
                    category=task.category,
                    outcome=TaskOutcome.FAILED,
                    detail=message,
                ),
                {},
            )

        if isinstance(produced, TaskData):
            payload, partial_reason = produced.data, produced.partial_reason
        else:  # a task that cannot be partial returns a plain dict
            payload, partial_reason = produced, None

        count = sum(len(v) for v in payload.values() if isinstance(v, list | dict))
        if partial_reason:
            log.warning(
                "collection.task_partial", task=task.key, reason=partial_reason
            )
            return (
                TaskResult(
                    key=task.key,
                    category=task.category,
                    outcome=TaskOutcome.PARTIAL,
                    detail=partial_reason,
                    item_count=count,
                ),
                payload,
            )

        return (
            TaskResult(
                key=task.key,
                category=task.category,
                outcome=TaskOutcome.COMPLETE,
                item_count=count,
            ),
            payload,
        )
