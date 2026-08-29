from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import ScanStatus


class ScanCreate(BaseModel):
    cloud_account_id: UUID


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    # One of these says what the scan covered. ``connection_id`` is the
    # tenant-wide form; ``cloud_account_id`` is a single subscription.
    cloud_account_id: UUID | None = None
    connection_id: UUID | None = None
    status: ScanStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    resource_count: int
    rule_count: int
    finding_count: int
    error_message: str | None = None
    collection_errors: dict = Field(default_factory=dict)
    created_at: datetime
    # True when nothing has collected this scan for long enough that a worker
    # is probably not running at all.
    stuck_in_queue: bool = False

    triggered_by_user_id: UUID | None = None
    # Set when this run re-evaluated an earlier scan's snapshot rather than
    # collecting. ``evaluation_only`` says it re-evaluated a capture that is no
    # longer current, so its counts describe what the rules would have found and
    # no finding was created, resolved or reopened.
    replay_of_scan_id: UUID | None = None
    evaluation_only: bool = False
    progress_done: int = 0
    progress_total: int = 0
    # Live while running, fixed once finished.
    duration_seconds: int | None = None


class ScanDetailOut(ScanOut):
    """A single scan with everything the detail panel shows.

    Separate from ``ScanOut`` because the list renders dozens of these and none
    of it is cheap: the scope panel reads two more tables and the breakdown
    aggregates findings.
    """

    scope: dict = Field(default_factory=dict)
    findings_by_severity: dict = Field(default_factory=dict)
    # How many unresolved findings a purge would take with it, so the
    # confirmation can state a number rather than a category.
    purgeable_finding_count: int = 0


class CoverageOut(BaseModel):
    """Reported separately from the security score on purpose.

    Folding coverage into the score would make "why is my score 84?"
    unanswerable without also explaining coverage maths (RISK_ENGINE.md 3).
    """

    coverage_ratio: float
    evaluated: int
    conclusive: int
    unknown: int
    gaps: list[dict] = Field(default_factory=list)
