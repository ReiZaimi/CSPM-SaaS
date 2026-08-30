from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import FindingStatus, Level, Priority, RemediationStatus, RiskKind, Severity


class ResourceSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    resource_type: str
    region: str | None = None
    environment: str | None = None
    criticality: Level
    data_sensitivity: Level
    public_exposure: Level


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: str
    severity: Severity
    status: FindingStatus
    title: str
    description: str
    evidence: dict = Field(default_factory=dict)
    remediation: str
    rule_version: str
    risk_score: float | None = None
    first_detected_at: datetime
    last_detected_at: datetime
    resolved_at: datetime | None = None
    resolved_by_scan_id: UUID | None = None
    resource: ResourceSummary | None = None


class RiskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    # Whether this is one observation scored for its asset, or several of them
    # seen as a route. The two rank against each other in the same list, so the
    # list has to say which is which.
    kind: RiskKind = RiskKind.FINDING
    # The route, hop by hop. Empty for a finding risk, which is about one asset
    # and has no route to describe.
    path: list = Field(default_factory=list)
    title: str
    description: str
    risk_score: float
    risk_level: Level
    status: str
    asset_criticality: Level
    data_sensitivity: Level
    internet_exposure: Level
    exploitability: float
    business_impact: float
    score_breakdown: dict = Field(default_factory=dict)
    due_date: date | None = None


class FindingDetail(FindingOut):
    """Everything the finding detail page needs to answer WHAT / WHY / HOW BAD /
    HOW DO I FIX IT / DID THE FIX WORK (UI.md section 3)."""

    rule_name: str | None = None
    rationale: str | None = None
    category: str | None = None
    compliance_mappings: dict = Field(default_factory=dict)
    estimated_effort_minutes: int = 30
    risk: RiskOut | None = None
    priority: Priority | None = None


class AcceptRiskRequest(BaseModel):
    reason: str = Field(min_length=10, max_length=2000)
    expires_at: datetime | None = None


class RemediationCreate(BaseModel):
    finding_id: UUID
    assigned_to: UUID | None = None
    due_date: date | None = None
    notes: str | None = Field(default=None, max_length=2000)


class RemediationUpdate(BaseModel):
    status: RemediationStatus | None = None
    assigned_to: UUID | None = None
    due_date: date | None = None
    notes: str | None = Field(default=None, max_length=2000)


class RemediationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    finding_id: UUID
    risk_id: UUID | None = None
    assigned_to: UUID | None = None
    status: RemediationStatus
    priority: Priority
    due_date: date | None = None
    estimated_effort_minutes: int
    notes: str | None = None
    completed_at: datetime | None = None
    created_at: datetime
