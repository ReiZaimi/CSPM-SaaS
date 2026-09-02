"""Celery application.

The worker shares the entire codebase with the API -- same models, same rule
engine, same risk engine. That is the modular monolith working as intended: a
scan is a long-running operation, not a separate service.
"""

from celery import Celery

from app.core.config import settings

# The queues a step is routed to, by what the step actually costs.
#
# Collection is IO-bound: it waits on Azure, holds little memory, and wants as
# many in flight as the provider's throttling allows. Analysis is the opposite
# -- it holds a whole tenant's resources and relationship index in memory while
# the rules run, and wants few. Sharing one pool means an analysis of a large
# tenant occupies a slot a collection could have used, and sizing the pool for
# one profile is sizing it wrongly for the other.
#
# One worker consuming all three is the default and needs no deployment change.
# Splitting them is then a second service with ``-Q analyze --concurrency=1``
# and the first narrowed to ``-Q celery,collect``.
COLLECT_QUEUE = "collect"
ANALYZE_QUEUE = "analyze"
# Everything else: starting a scan, advancing it, reaping, replay. All short,
# all database-only.
DEFAULT_QUEUE = "celery"

celery_app = Celery(
    "cloudguard",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.workers.scan_tasks"],
)

celery_app.conf.beat_schedule = {
    # Frequent because what it clears is a lockout, not a mess. A scan whose
    # worker died leaves its connection unscannable until something closes the
    # row, and the customer's experience in the meantime is a button that
    # answers "a scan is already running" for ever.
    "reap-abandoned-scans": {
        "task": "cloudguard.reap_abandoned_scans",
        "schedule": 60.0,
    },
    # Every five minutes rather than hourly. The interval a customer sets is a
    # floor on how often their environment is read, and a coarse tick would
    # quietly add up to half an hour to it -- a daily scan is then daily plus
    # whenever the scheduler next happens to look.
    "start-due-scans": {
        "task": "cloudguard.start_due_scans",
        "schedule": 300.0,
    },
    # A minute, because the first attempt is owed five minutes after a customer
    # says they have fixed something and a coarse tick would double that. The
    # sweep is a bounded query against a partial index over pending rows, so
    # looking often costs almost nothing and waiting costs the customer the one
    # answer they are actually sitting there waiting for.
    # A minute, matching the verification sweep and for the same reason: the
    # quiet period is measured in minutes, and a coarse tick would add its own
    # interval to every customer's wait for a scan they can see the reason for.
    "scan-changed-environments": {
        "task": "cloudguard.scan_changed_environments",
        "schedule": 60.0,
    },
    "verify-due-remediations": {
        "task": "cloudguard.verify_due_remediations",
        "schedule": 60.0,
    },
    # Five minutes, not one. Nothing here is a lockout and nothing is waiting on
    # it: a notification is news, and news five minutes old is news. The sweep
    # loads a graph per organization, which is the one part of it that is not
    # free, so looking often would cost more than the freshness is worth.
    "derive-notifications": {
        "task": "cloudguard.derive_notifications",
        "schedule": 300.0,
    },
}

celery_app.conf.update(
    task_default_queue=DEFAULT_QUEUE,
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
