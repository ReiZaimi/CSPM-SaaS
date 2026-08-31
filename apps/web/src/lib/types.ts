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
  /**
   * Whether this is one observation scored for its asset, or several of them
   * seen as a route. Both rank in the same list — a combination outranking its
   * parts is only visible where they are listed together.
   */
  kind: "FINDING" | "ATTACK_PATH" | "ESCALATION";
  /** The route, hop by hop. Empty for a finding risk, which has none. */
  path: AttackPathStep[];
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
    /** Present on a finding risk: the six weighted components. */
    components?: Record<string, { value: number; weight: number; contribution: number }>;
    /**
     * Present on a scenario risk instead. The floor is the worst member's
     * score, so the number is visibly built on evidence rather than decided.
     * `uncapped` exists so a score of 100 can explain why it is not 101.
     */
    worst_member?: number;
    amplifier?: number;
    hops?: number;
    uncapped?: number;
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

/** One transition in a finding's life, and who or what caused it. */
export interface FindingEvent {
  event: "DETECTED" | "REOPENED" | "RESOLVED" | "RISK_ACCEPTED" | "STATUS_CHANGED";
  previous_status: string | null;
  current_status: string;
  scan_id: string | null;
  user_id: string | null;
  detail: string | null;
  observed_at: string;
}

/**
 * Where a claimed fix has got to.
 *
 * Three ways of not being verified, and they are different news for different
 * people: the fix did not work, CloudGuard could not see, or it is simply too
 * soon. `detail` is the sentence written for the reader; the status is what the
 * UI colours on.
 */
export interface Verification {
  status: "PENDING" | "VERIFIED" | "STILL_FAILING" | "INSUFFICIENT_EVIDENCE" | "ABANDONED";
  claimed_at: string;
  expected_state: { field: string; comparison: string; describes: string }[];
  attempts: number;
  last_state: string | null;
  next_attempt_at: string | null;
  settled_at: string | null;
  detail: string | null;
}

/** What must become true for a finding to close, and how to make it so. */
export interface RemediationSpec {
  expected_state: {
    field: string;
    comparison: string;
    describes: string;
    equals?: unknown;
    also_accepts?: unknown[];
    example?: unknown;
  }[];
  cli: string[];
  terraform: { attribute: string; value: string; describes: string }[];
  azure_policy: Record<string, unknown> | null;
  enforceable: boolean;
  applies_when?: Record<string, unknown>;
  notes: string;
}

export interface FindingDetail extends Finding {
  rule_name?: string;
  rationale?: string;
  category?: string;
  compliance_mappings?: Record<string, string[]>;
  estimated_effort_minutes?: number;
  risk?: Risk | null;
  priority?: string;
  remediation_spec?: RemediationSpec | null;
  verification?: Verification | null;
  timeline?: FindingEvent[];
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
  /** Queued long enough that no worker is likely running. */
  stuck_in_queue?: boolean;
  triggered_by_user_id?: string | null;
  /**
   * Why this scan ran. Read this rather than inferring it from a missing user:
   * an old manual scan whose user record has gone also has no
   * `triggered_by_user_id`, and calling that one "Scheduled" is simply wrong.
   */
  trigger?: "MANUAL" | "SCHEDULED";
  progress_done?: number;
  progress_total?: number;
  /** Live while running, fixed once finished. */
  duration_seconds?: number | null;
}

/** What the posture was, one scan at a time. */
export interface PostureReading {
  observed_at: string;
  security_score: number;
  open_finding_count: number;
  findings_by_severity: Record<string, number>;
  risk_bands: Record<string, number>;
  attack_path_count: number;
}

export interface Dashboard {
  security_score: number;
  /**
   * Movement since the previous reading. Measured, so it can be negative —
   * the estimate it replaced added back every fix ever verified and could only
   * ever be positive. `null` means there is no previous reading to compare
   * against, which is not the same as no change.
   */
  score_delta: number | null;
  history: PostureReading[];
  findings_by_severity: Record<string, number>;
  findings_by_status: Record<string, number>;
  risk_bands: Record<string, number>;
  open_finding_count: number;
  asset_count: number;
  verified_resolved_last_30_days: number;
  remediation_rate: number;
  top_risks: { id: string; title: string; risk_score: number; risk_level: Level }[];
  coverage: { ratio: number | null; unknown: number; conclusive: number };
  /**
   * How recently the provider was actually read, which is a different question
   * from coverage: a posture can be fully covered and three weeks out of date.
   * Measured over the newest reading of each scope and evidence key, so the
   * headline is the *oldest* of them.
   */
  evidence_freshness?: {
    readings: number;
    oldest_at: string | null;
    newest_at: string | null;
    stale_hours: number | null;
    unusable: number;
  } | null;
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

export interface CloudConnection {
  id: string;
  provider: string;
  name: string;
  scope_type: ConnectionScope;
  scope_id: string | null;
  scope_path: string | null;
  role_version: string;
  tenant_id: string | null;
  service_principal_object_id: string | null;
  consent_status: "PENDING" | "GRANTED" | "REVOKED";
  consented_at: string | null;
  rbac_verified_at: string | null;
  status: "PENDING" | "ACTIVE" | "ERROR" | "DISABLED";
  status_detail: string | null;
  last_discovery_at: string | null;
  /**
   * How often this environment is re-read, in hours. `null` means manual only,
   * which is where every connection starts: scheduling a customer's cloud
   * without being asked is a recurring cost on their Azure bill.
   */
  scan_interval_hours: number | null;
  created_at: string;
  is_verified: boolean;
  is_ready_to_scan: boolean;
  subscription_count: number;
  subscriptions: DiscoveredSubscription[];
  consent_url: string | null;
  template_url: string | null;
  /** True once waiting no longer explains why read access has not appeared. */
  deploy_stalled: boolean;
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

/**
 * A route from somewhere an attacker could start to something worth taking.
 *
 * The findings list answers "what is wrong". This answers "what is wrong
 * *together*", which is a different question with a different first action:
 * five findings across a jump box, an identity and a storage account rank by
 * severity and get worked top-down, while the same five as one path rank by how
 * few hops separate the internet from customer data.
 */
export interface AttackPath {
  entry: {
    id: string;
    name: string;
    resource_type: string;
    public_exposure: string;
  };
  target: {
    id: string;
    name: string;
    resource_type: string;
    data_sensitivity: string;
  };
  hops: number;
  steps: AttackPathStep[];
  /**
   * Where to cut it. Always a capability hop — containment cannot be removed,
   * since a storage account has to live somewhere.
   */
  cheapest_break: {
    description: string;
    relationship: string;
    source_id: string;
    target_id: string;
  } | null;
}

export interface AttackPathStep {
  source: string;
  source_id: string;
  relationship: string;
  target: string;
  target_id: string;
  description: string;
}

/**
 * Both counts are the honest denominator for an empty answer: no paths because
 * nothing is exposed is a different thing from no paths because nothing was
 * classified as sensitive.
 */
export interface AttackPathMeta {
  total: number;
  entry_points: number;
  sensitive_targets: number;
}

export interface RevocationStep {
  title: string;
  detail: string;
  command: string;
}

export interface Revocation {
  principal_id: string | null;
  scope_path: string | null;
  role_name: string;
  tenant_id: string | null;
  steps: RevocationStep[];
  /** Why CloudGuard cannot do this itself. */
  why_manual: string;
  portal_url: string;
}

export interface RevocationCheck {
  revoked: boolean;
  detail: string;
}

export interface ScanScope {
  subscription_id: string | null;
  subscription_name: string | null;
  tenant_id: string | null;
  connection_name: string | null;
  scope_type: string | null;
  scope_path: string | null;
  service_principal_object_id: string | null;
  role_version: string | null;
}

export interface ScanDetail extends Scan {
  scope: ScanScope;
  findings_by_severity: Record<string, number>;
  /** How many unresolved findings a purge would take with it. */
  purgeable_finding_count: number;
}

export interface WorkerStatus {
  workers: number;
  /** False when the broker itself could not be reached. */
  reachable: boolean;
  detail: string;
}

/**
 * What a scan managed to read, per subscription and per collection task.
 *
 * Separate from rule coverage, which reports what the checks concluded. This
 * reports whether they were entitled to conclude anything — and in particular
 * distinguishes a category that failed outright from one that came back
 * truncated. An outage and a tenant larger than one scan reads used to arrive
 * as the same sentence.
 */
export type CollectionOutcome = "COMPLETE" | "PARTIAL" | "FAILED" | "SKIPPED";

export interface CollectionReading {
  subscription: string | null;
  cloud_account_id: string;
  task: string;
  category: string;
  outcome: CollectionOutcome;
  detail: string | null;
  item_count: number;
}

export interface CollectionStatus {
  tasks: CollectionReading[];
  total: number;
  complete: number;
  partial: number;
  failed: number;
  skipped: number;
  degraded_categories: string[];
}
