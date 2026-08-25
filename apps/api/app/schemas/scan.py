from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import ScanStatus


class ScanCreate(BaseModel):
    cloud_account_id: UUID


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    cloud_account_id: UUID
    status: ScanStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    resource_count: int
    rule_count: int
    finding_count: int
    error_message: str | None = None
    collection_errors: dict = Field(default_factory=dict)
    created_at: datetime


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
