"""The worker runs each task in its own event loop.

asyncpg binds a connection to the loop that opened it, and the engines in
``app.core.db`` are cached for the life of the *process*. So a pooled
connection outlives the loop that created it, and the next task is handed
something belonging to a loop that has already closed:

    RuntimeError: got Future attached to a different loop
    RuntimeError: Event loop is closed

The failure is unusually good at hiding. The first scan in each worker child
succeeds, so a deployment looks healthy right up until the second one -- and
with prefork concurrency the number of free scans equals the number of
children, which reads like an intermittent fault rather than a certainty.
"""

import asyncio
from typing import ClassVar
from uuid import uuid4

import pytest

from app.workers import scan_tasks


class RecordingPipeline:
    """Stands in for the scan, and remembers which loop it ran on."""

    loops: ClassVar[list[asyncio.AbstractEventLoop]] = []

    def __init__(self, scan_id: object) -> None:
        self.scan_id = scan_id

    async def run(self) -> None:
        RecordingPipeline.loops.append(asyncio.get_running_loop())


@pytest.fixture
def instrumented(monkeypatch: pytest.MonkeyPatch) -> dict:
    RecordingPipeline.loops = []
    disposals: list[asyncio.AbstractEventLoop] = []

    async def fake_dispose() -> None:
        disposals.append(asyncio.get_running_loop())

    monkeypatch.setattr(scan_tasks, "ScanPipeline", RecordingPipeline)
    monkeypatch.setattr(scan_tasks, "dispose_engines", fake_dispose)
    return {"disposals": disposals}


async def test_connections_are_released_before_the_loop_closes(instrumented) -> None:
    """Disposal has to happen *inside* the task's loop.

    Afterwards there would be no loop left to close the connections on, which
    is exactly the thing that has gone wrong.
    """
    await scan_tasks._run_and_release(uuid4())

    assert len(instrumented["disposals"]) == 1
    assert instrumented["disposals"][0] is RecordingPipeline.loops[0]


async def test_a_failing_scan_still_releases_its_connections(
    instrumented, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Otherwise one bad scan poisons every later scan in that worker."""

    class FailingPipeline(RecordingPipeline):
        async def run(self) -> None:
            await super().run()
            raise RuntimeError("Azure exploded")

    monkeypatch.setattr(scan_tasks, "ScanPipeline", FailingPipeline)

    with pytest.raises(RuntimeError, match="Azure exploded"):
        await scan_tasks._run_and_release(uuid4())

    assert len(instrumented["disposals"]) == 1


def test_consecutive_tasks_each_get_a_fresh_loop(instrumented) -> None:
    """The condition that made this a bug: every task is a new loop.

    Two runs, two loops, and a disposal inside each. Without the disposal the
    second would inherit the first loop's connections.
    """
    for _ in range(2):
        asyncio.run(scan_tasks._run_and_release(uuid4()))

    assert len(RecordingPipeline.loops) == 2
    assert RecordingPipeline.loops[0] is not RecordingPipeline.loops[1]
    assert instrumented["disposals"] == RecordingPipeline.loops
