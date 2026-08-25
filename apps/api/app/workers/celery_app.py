"""Celery application.

The worker shares the entire codebase with the API -- same models, same rule
engine, same risk engine. That is the modular monolith working as intended: a
scan is a long-running operation, not a separate service.
"""

from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "cloudguard",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.workers.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    # A scan is bounded work; a stuck Azure call should surface as a failed scan
    # rather than a worker that never comes back.
    task_time_limit=1800,
    task_soft_time_limit=1500,
    worker_max_tasks_per_child=50,
    broker_connection_retry_on_startup=True,
)
