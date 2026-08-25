"""Scan tasks.

The task takes only a scan id. Everything else -- organization, cloud account,
subscription -- is read from that record inside the worker, so a queue message
can never be the source of a tenant boundary decision.
"""

import asyncio
from uuid import UUID

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
    asyncio.run(ScanPipeline(UUID(scan_id)).run())
    return {"scan_id": scan_id}
