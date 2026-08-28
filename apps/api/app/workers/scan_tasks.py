"""Scan tasks.

The task takes only a scan id. Everything else -- organization, cloud account,
subscription -- is read from that record inside the worker, so a queue message
can never be the source of a tenant boundary decision.
"""

import asyncio
from uuid import UUID

from app.core.db import dispose_engines
from app.core.logging import configure_logging, get_logger
from app.services.scanner import ScanPipeline
from app.workers.celery_app import celery_app

log = get_logger(__name__)


@celery_app.task(name="cloudguard.run_scan", bind=True, max_retries=0)
def run_scan(self: object, scan_id: str) -> dict:
    """Execute one scan end to end.

    Deliberately no retries: a scan that failed halfway has already recorded why
    on the scan row, and silently re-running it would double-write findings. The
    user re-scans when they are ready.
    """
    configure_logging()
    log.info("scan.task_received", scan_id=scan_id)
    asyncio.run(_run_and_release(UUID(scan_id)))
    return {"scan_id": scan_id}


async def _run_and_release(scan_id: UUID) -> None:
    """Run the pipeline, then hand back the connections before the loop dies.

    ``asyncio.run`` gives every task its own event loop, while the engine pool
    is cached for the life of the process. Without the disposal below the second
    scan in a worker inherits connections bound to the first scan's loop, which
    by then is closed -- the first scan succeeds, every later one fails with
    "got Future attached to a different loop". Prefork makes that especially
    confusing: each child gets exactly one working scan.
    """
    try:
        await ScanPipeline(scan_id).run()
    finally:
        await dispose_engines()
