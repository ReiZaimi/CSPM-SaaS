export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type Level = Severity | "UNKNOWN";
export type FindingStatus =
  | "OPEN"
  | "IN_PROGRESS"
  | "RESOLVED"
  | "ACCEPTED_RISK"
  | "FALSE_POSITIVE";

export interface Organization {
  id: string;
  name: string;
  slug: string;
  industry: string | null;
  country: string | null;
  created_at: string;
  role?: string;
}

export interface CloudAccount {
  id: string;
  provider: string;
  account_name: string;
  tenant_id: string;
  subscription_id: string | null;
  consent_status: "PENDING" | "GRANTED" | "REVOKED";
  rbac_verified_at: string | null;
  status: "PENDING" | "ACTIVE" | "ERROR" | "DISABLED";
  status_detail: string | null;
  last_scan_at: string | null;
  is_scannable: boolean;
}

export interface ResourceSummary {
  id: string;
  name: string;
  resource_type: string;
  region: string | null;
  environment: string | null;
  criticality: Level;
  data_sensitivity: Level;
  public_exposure: Level;
}

export interface Asset extends ResourceSummary {
  open_findings: number;
  first_seen_at: string;
  last_seen_at: string;
}

export interface Risk {
  id: string;
  title: string;
  description: string;
  risk_score: number;
  risk_level: Level;
  status: string;
  asset_criticality: Level;
  data_sensitivity: Level;
  internet_exposure: Level;
  exploitability: number;
  business_impact: number;
  score_breakdown: {
    components?: Record<string, { value: number; weight: number; contribution: number }>;
    total?: number;
  };
}

export interface Finding {
  id: string;
  rule_id: string;
  severity: Severity;
  status: FindingStatus;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  remediation: string;
  rule_version: string;
  risk_score: number | null;
  first_detected_at: string;
  last_detected_at: string;
  resolved_at: string | null;
  resolved_by_scan_id: string | null;
  resource: ResourceSummary | null;
}

export interface FindingDetail extends Finding {
  rule_name?: string;
  rationale?: string;
  category?: string;
  compliance_mappings?: Record<string, string[]>;
  estimated_effort_minutes?: number;
  risk?: Risk | null;
  priority?: string;
}

export interface Scan {
  id: string;
  cloud_account_id: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  resource_count: number;
  rule_count: number;
  finding_count: number;
  error_message: string | null;
  collection_errors: Record<string, string>;
  created_at: string;
}

export interface Dashboard {
  security_score: number;
  score_delta: number | null;
  findings_by_severity: Record<string, number>;
  findings_by_status: Record<string, number>;
  risk_bands: Record<string, number>;
  open_finding_count: number;
  asset_count: number;
  verified_resolved_last_30_days: number;
  remediation_rate: number;
  top_risks: { id: string; title: string; risk_score: number; risk_level: Level }[];
  coverage: { ratio: number | null; unknown: number; conclusive: number };
  last_scan: {
    id: string;
    status: string;
    completed_at: string | null;
    resource_count: number;
    rule_count: number;
    finding_count: number;
    collection_errors: Record<string, string>;
  } | null;
}

export interface Rule {
  rule_id: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  version: string;
  exploitability: number;
  scope: string;
  applies_to: string[];
  enabled: boolean;
  remediation: string;
  rationale: string;
  estimated_effort_minutes: number;
  compliance_mappings: Record<string, string[]>;
}

export interface RemediationTask {
  id: string;
  finding_id: string;
  risk_id: string | null;
  status: "TODO" | "IN_PROGRESS" | "DONE" | "CANCELLED";
  priority: Severity;
  due_date: string | null;
  estimated_effort_minutes: number;
  notes: string | null;
  completed_at: string | null;
  created_at: string;
}

/** Compliance coverage. Mirrors app/compliance/coverage.py::ControlStatus. */
export type ControlStatus =
  | "FAILING"
  | "INCONCLUSIVE"
  | "PASSING"
  | "NOT_ASSESSED"
  | "NOT_COVERED";

export interface ControlRuleEvidence {
  rule_id: string;
  name: string;
  severity: string;
  open_finding_count: number;
  unknown_count: number;
  evaluated: boolean;
}

export interface ComplianceControl {
  id: string;
  title: string;
  group: string;
  /** False where the requirement is organizational — no scanner can observe it. */
  technically_assessable: boolean;
  status: ControlStatus;
  open_finding_count: number;
  rules: ControlRuleEvidence[];
}

export interface ComplianceFramework {
  id: string;
  name: string;
  short_name: string;
  version: string;
  authority: string;
  url: string;
  summary: string;
  scope_note: string;
  control_count: number;
  status_counts: Record<ControlStatus, number>;
  /** Share of catalogued controls CloudGuard reached a conclusion on. */
  coverage_ratio: number | null;
  open_finding_count: number;
}

export interface ComplianceFrameworkDetail extends ComplianceFramework {
  assessed: boolean;
  controls: ComplianceControl[];
}

/** Cloud connections. Mirrors app/models/cloud_connection.py. */
export type ConnectionScope = "TENANT_ROOT" | "MANAGEMENT_GROUP" | "SUBSCRIPTION";
export type PermissionMode = "READER" | "CUSTOM_ROLE";
export type ArtifactFormat = "cli" | "bicep" | "terraform";

export interface CloudConnection {
  id: string;
  provider: string;
  name: string;
  scope_type: ConnectionScope;
  scope_id: string | null;
  /** The ARM scope a grant is written at. Null until consent names the tenant. */
  scope_path: string | null;
  permission_mode: PermissionMode;
  role_version: string;
  /** Null until Entra's consent callback reports it — never typed by anyone. */
  tenant_id: string | null;
  service_principal_object_id: string | null;
  consent_status: "PENDING" | "GRANTED" | "REVOKED";
  consented_at: string | null;
  rbac_verified_at: string | null;
  external_id_verified: boolean;
  status: "PENDING" | "ACTIVE" | "ERROR" | "DISABLED";
  status_detail: string | null;
  last_discovery_at: string | null;
  created_at: string;
  is_verified: boolean;
  subscription_count: number;
}

export interface DiscoveredSubscription {
  id: string;
  subscription_id: string | null;
  display_name: string | null;
  in_scope: boolean;
  status: "PENDING" | "ACTIVE" | "ERROR" | "DISABLED";
  discovered_at: string | null;
  last_scan_at: string | null;
  is_scannable: boolean;
}

export interface ConnectionChoice {
  value: string;
  label: string;
  detail: string;
  requires_scope_id?: boolean;
  action_count?: number | null;
}

export interface ConnectionOptions {
  /** False when this deployment has no Entra app identity — consent cannot start. */
  azure_configured: boolean;
  scopes: ConnectionChoice[];
  permission_modes: ConnectionChoice[];
  formats: string[];
  graph_permissions: string[];
  arm_actions: string[];
  role_version: string;
  provider: string;
}

export interface ArtifactLinks {
  formats: Record<string, string>;
  expires_in_seconds: number;
  scope_path: string | null;
  principal_id: string | null;
  permission_mode: PermissionMode;
  arm_actions: string[];
  cloud_shell_url: string;
}

export interface ValidationResult {
  ok: boolean;
  detail: string;
  permissions_verified: string[];
  problems: string[];
  subscription_id: string | null;
}
