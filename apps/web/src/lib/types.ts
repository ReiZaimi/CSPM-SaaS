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

/**
 * What a customer has said about a subscription that CloudGuard could not
 * discover.
 *
 * The risk engine multiplies a finding's severity by asset criticality, data
 * sensitivity and exposure — so a declaration is the highest-leverage input a
 * customer can give, and it beats anything inferred from a name or a tag.
 *
 * A statement rather than a profile: the PUT replaces the whole thing, and a
 * field left out is one the customer is no longer claiming.
 */
export interface ContextDeclaration {
  cloud_account_id: string;
  environment: string | null;
  criticality: Level | null;
  data_sensitivity: Level | null;
  note: string | null;
  declared_by_user_id: string | null;
  declared_at: string;
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
  /**
   * The provider's own identifier. Carries the hierarchy: an ARM id states its
   * own subscription and resource group, which is the only way to say where an
   * asset sits without a request per row.
   */
  provider_resource_id: string;
  /**
   * The provider's own type, for resources CloudGuard has no rule for.
   *
   * `resource_type` is the cloud-neutral one the rules match on, and it is
   * `"unknown"` for anything the connector does not model. A row reading
   * "Unknown" would be a worse answer than the omission it replaced -- the
   * point of listing these is that the customer can see *what* is unchecked --
   * so the real type travels beside it. Null for a modelled asset, whose
   * neutral type is already the better label.
   */
  azure_type: string | null;
  open_findings: number;
  first_seen_at: string;
  last_seen_at: string;
}

/**
 * The estate as it is organised, counted over the whole of it.
 *
 * Subscriptions (and the directory, which belongs to no subscription) each
 * holding their resource groups. A group's `name` is null where the asset sits
 * directly in the subscription rather than in a group — left null rather than
 * called "Ungrouped", which would read as somebody's oversight.
 */
export interface AssetScopeNode {
  id: string;
  name: string;
  kind: "SUBSCRIPTION" | "DIRECTORY";
  asset_count: number;
  open_findings: number;
  groups: {
    name: string | null;
    asset_count: number;
    open_findings: number;
  }[];
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

/**
 * One risk, with the findings it was built from.
 *
 * The list can rank a scenario above the findings inside it; only here can a
 * reader see *which* findings those are. A route scored 96 beside a page of
 * findings scored 84 is an assertion until the members are named.
 */
export interface RiskDetail extends Risk {
  /**
   * When the route was last seen, not when it first appeared.
   *
   * `null` where the scan that saw it has been pruned, or where the route
   * predates this being tracked. Both mean "we cannot say when" and must not
   * render as "just now".
   */
  observed_at?: string | null;
  findings: {
    id: string;
    rule_id: string;
    title: string;
    severity: Level;
    status: string;
  }[];
}

export interface Finding {
  id: string;
  rule_id: string;
  severity: Severity;
  status: FindingStatus;
  title: string;
  description: string;
  /**
   * What the rule saw. `compensating_controls` is added by the pipeline rather
   * than by any rule: defences observed in the same capture that make this
   * finding harder to exploit without making it right, so they lower what it is
   * scored at and never resolve it.
   */
  evidence: Record<string, unknown> & {
    compensating_controls?: {
      id: string;
      name: string;
      detail: string;
      exploitability: number;
    }[];
  };
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
  /**
   * Set when this run re-evaluated an earlier scan's stored snapshot rather
   * than reading the cloud. Nothing here cost the customer an Azure call.
   */
  replay_of_scan_id?: string | null;
  /**
   * True when the replayed capture is no longer the newest one for its
   * account. Its counts then say what today's rules *would* have found, and
   * no finding was created, resolved or reopened — a month-old capture is
   * evidence about last month, and "verified fixed" may not rest on it.
   */
  evaluation_only?: boolean;
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
  /**
   * What actually happened, week by week: findings raised, verified fixed, and
   * come back. Read from the transition log rather than from the findings
   * themselves — `first_detected_at` and `resolved_at` are two points on a
   * line, and a finding fixed twice looks like one fixed once.
   */
  remediation_activity?: {
    week: string;
    detected: number;
    resolved: number;
    reopened: number;
  }[];
  top_risks: {
    id: string;
    title: string;
    risk_score: number;
    risk_level: Level;
    /** A finding scored for its asset, or several of them seen as a route. */
    kind?: "FINDING" | "ATTACK_PATH";
    /** The terms the score was built from, so a rank can be read as a reason. */
    internet_exposure?: Level;
    data_sensitivity?: Level;
    asset_criticality?: Level;
  }[];
  coverage: {
    ratio: number | null;
    unknown: number;
    conclusive: number;
    /**
     * Which parts of the estate the last scan could read. A ratio says how much
     * is missing and never which part, and those call for different actions.
     * `incomplete` counts PARTIAL with FAILED: a truncated listing cannot
     * support "none of them are public".
     */
    categories?: { name: string; readings: number; incomplete: number }[];
    /**
     * The other half of coverage. A check that reached no verdict is missing
     * evidence and never becomes a finding, so it never touched the score. An
     * asset whose criticality or data sensitivity CloudGuard could not
     * establish is missing *context*, and the risk formula ranks that just
     * under High so an unlabelled asset never sorts below a labelled one — a
     * caution that is right for the ordering and must not reach the posture
     * number. So the score charges the established band, and what the caution
     * would have added is reported here: label these assets and the score moves.
     */
    context: { unclassified: number; classified: number; ratio: number };
  };
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
  provider: string;
  severity: Severity;
  version: string;
  exploitability: number;
  scope: string;
  applies_to: string[];
  /**
   * False once the rule has been withdrawn from the registry — it no longer
   * runs, and compliance coverage stops counting it. The row survives because
   * findings it raised in the past still name it.
   */
  enabled: boolean;
  remediation: string;
  rationale: string;
  estimated_effort_minutes: number;
  compliance_mappings: Record<string, string[]>;
  /** What "fixed" means for this rule: the settings, commands and policy. */
  remediation_spec?: RemediationSpec | null;
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
  /**
   * Why the rule could not tell, in its own words.
   *
   * INCONCLUSIVE is the one verdict on a control card a reader cannot act on
   * from the verdict alone: failing points at findings, passing needs nothing,
   * not-covered is a fact about CloudGuard. "Three could not be evaluated"
   * points nowhere — and the answer is frequently a scanner role that needs
   * redeploying, which is a thing they can do today.
   *
   * Several because one rule can fail differently on different resources.
   */
  unknown_reasons: string[];
  evaluated: boolean;
}

/**
 * One provider listing a control's verdict rests on.
 *
 * Present for a passing control as much as a failing one, which is the point:
 * a finding cites the readings behind it, so "how do you know this is wrong"
 * was answerable and "how do you know this is met" was not.
 */
export interface ControlReading {
  evidence_key: string;
  /** `null` where the latest scan holds no reading of this key — not the same
   *  as a failed read, and rendered differently. */
  outcome: "COMPLETE" | "PARTIAL" | "FAILED" | null;
  /** How many subscriptions (plus the directory) this listing was taken across. */
  scopes: number;
  collected_at: string | null;
  age_seconds: number | null;
  permissions: string[];
  /** Whether every payload behind it is still stored, so it can still be
   *  followed back to the bytes. */
  retained: boolean;
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
  readings: ControlReading[];
}

/** Which reading of the estate an assessment is of. `null` before the first
 *  scan completes: a framework page is then a catalogue, not an assessment. */
export interface ComplianceAssessment {
  scan_id: string;
  completed_at: string | null;
  scan_status: string;
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
  assessment: ComplianceAssessment | null;
  controls: ComplianceControl[];
}

/** Cloud connections. Mirrors app/models/cloud_connection.py. */

/** Which cloud a connection reads. */
export type Provider = "azure" | "aws";

/**
 * How much of a cloud one connection covers.
 *
 * One union across both clouds, because it is one question with a different
 * vocabulary each time: a trust boundary, a grouping inside it, and the unit a
 * scan reads. Named in each provider's own words rather than abstracted --
 * whoever reads a row is usually matching it against a portal that says
 * "management group" or "organizational unit".
 */
export type ConnectionScope =
  | "TENANT_ROOT"
  | "MANAGEMENT_GROUP"
  | "SUBSCRIPTION"
  | "ORGANIZATION"
  | "ORGANIZATIONAL_UNIT"
  | "ACCOUNT";

/** What a deployment can actually connect, and why not. */
export interface ProviderOption {
  id: Provider;
  name: string;
  available: boolean;
  /**
   * Why this cloud cannot be chosen here. Shown rather than hidden: a picker
   * that silently held an option answers "does this support AWS?" with
   * nothing.
   */
  unavailable_reason: string | null;
}

export interface CloudConnection {
  id: string;
  provider: Provider;
  name: string;
  scope_type: ConnectionScope;
  scope_id: string | null;
  scope_path: string | null;
  role_version: string;
  /**
   * Whether the deployed role is older than the one CloudGuard now needs.
   *
   * The version has been stamped on every connection since connections
   * existed; until the access panel read it back it was a label rather than a
   * mechanism. Shipping a check that needs a new ARM permission would leave
   * every existing customer collecting UNKNOWN for it, with the screen still
   * painting the role green.
   */
  role_upgrade_available: boolean;
  /** The role version CloudGuard needs today, to redeploy toward. */
  role_required_version: string;
  /**
   * Which collection categories the deployed role cannot fully serve. Empty
   * when it is current. Comes from the same function the scanner uses to
   * explain its gaps, so this screen and the scan cannot disagree.
   */
  degraded_categories: string[];
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
  /**
   * What only this connection's cloud has a word for, filtered by the API to
   * what a customer is meant to read.
   *
   * On AWS: the scanner role's ARN, and the external id its trust policy must
   * require. The external id is shown on purpose -- the customer needs it to
   * check their own trust policy, and it is not a credential: it means nothing
   * without a role that demands it. Empty for Azure, which keeps nothing per
   * customer.
   */
  provider_ref: { role_arn?: string; external_id?: string };
  /** True once waiting no longer explains why read access has not appeared. */
  deploy_stalled: boolean;
  /** Whether this environment reports its own changes, and when it last did. */
  change_events_enabled?: boolean;
  last_change_event_at?: string | null;
}

export interface DiscoveredSubscription {
  id: string;
  subscription_id: string | null;
  display_name: string | null;
  in_scope: boolean;
  /**
   * When the scope choice was last changed. Null on a subscription nobody has
   * ever ticked or unticked, which is every one of them until somebody does.
   */
  scope_changed_at?: string | null;
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

/**
 * A route seen from one asset on it. Same shape as an attack path, plus where
 * on the route the asset in question sits — which is what decides what a
 * reader should do about it.
 */
/**
 * One provider call a reading was made with.
 *
 * The api-version is the half that settles arguments: a field absent from a
 * capture is a setting nobody set, or a contract too old to return it, and only
 * the second is CloudGuard's own staleness.
 */
export interface ProviderEndpoint {
  path: string;
  api_version: string;
}

/**
 * One reading a finding rests on.
 *
 * The citation, not the excerpt. `evidence` on the finding is what the rule
 * saw; this is where it came from, and it is what turns "CloudGuard says this
 * is public" into something the customer can check.
 */
export interface EvidenceCitation {
  evidence_key: string;
  /** `null` is the directory: a tenant-wide read happened in no subscription. */
  cloud_account_id: string | null;
  /** `null` once the scan that read it has been pruned. */
  outcome: CollectionOutcome | null;
  item_count: number | null;
  permissions: string[];
  /** Empty where the scan was pruned, or the reading predates this being recorded. */
  endpoints: ProviderEndpoint[];
  content_hash: string | null;
  collected_at: string;
  /**
   * Computed by the API, not here. A carried reading is older than the scan
   * that raised the finding, and a browser measuring it against its own clock
   * would show a different age on every machine.
   */
  age_seconds: number;
  source_scan_id: string | null;
  /** Whether the payload is still stored. A pruned blob does not void the citation. */
  payload_available: boolean;
}

/**
 * `evidence: null` means no citation was recorded — a finding raised before
 * CloudGuard tracked this. An empty array would mean the rule reads nothing,
 * and the UI must not say the second when the API said the first.
 */
export interface FindingProvenance {
  rule_id: string;
  rule_version: string;
  evidence: EvidenceCitation[] | null;
}

export interface FindingAttackPath extends AttackPath {
  asset_role: "ENTRY" | "STEP" | "TARGET";
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

/**
 * One removable link, and the routes that stop existing without it.
 *
 * `severs` is verified by removing the link and re-asking the whole question,
 * so it is what actually closes. `on_routes` is the larger number of routes the
 * link merely sits on — carried beside it because the gap is the interesting
 * part: a link on twenty routes that closes three is a link with a way round.
 */
export interface ChokePoint {
  description: string;
  relationship: string;
  source: { id: string; name: string; resource_type: string };
  target: { id: string; name: string; resource_type: string };
  severs: number;
  on_routes: number;
  total_routes: number;
  closes: {
    entry: string;
    target: string;
    hops: number;
    data_sensitivity: Level;
  }[];
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

/**
 * One durable stage of a scan.
 *
 * A scan is not one task: it is PLAN, then a COLLECT per subscription plus one
 * for the tenant directory, then ANALYZE. Each is claimed under a lease and
 * retried on its own, which is why `attempt` matters — a step on its second
 * attempt is a step that was interrupted, and that is the first thing to know
 * about a scan taking twice as long as usual.
 */
export interface ScanStage {
  stage: "PLAN" | "COLLECT" | "ANALYZE";
  /** The subscription this stage read, or the tenant directory. */
  scope: string | null;
  status: "PENDING" | "RUNNING" | "SUCCEEDED" | "FAILED" | "SKIPPED";
  attempt: number;
  duration_seconds: number | null;
  error: string | null;
}

export interface ScanDetail extends Scan {
  scope: ScanScope;
  stages?: ScanStage[];
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
  /** The reading itself, so its finding count is followable to exactly those findings. */
  evidence_id: string;
  /**
   * How many findings cite this reading. Zero for a failed one, honestly: the
   * rules that needed it degraded to UNKNOWN and never became findings.
   */
  finding_count: number;
  collected_at: string;
  endpoints: ProviderEndpoint[];
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

/**
 * What happened to an asset between two readings of the same environment.
 *
 * Deliberately only five kinds. Configuration drift is not here — every field
 * of every payload would produce a feed nobody can read, and the drift that
 * matters already surfaces as a finding.
 */
export type AssetChange =
  | "APPEARED"
  | "DISAPPEARED"
  | "EXPOSURE_CHANGED"
  | "SENSITIVITY_CHANGED"
  | "CRITICALITY_CHANGED";

export interface ChangeEvent {
  id: string;
  change: AssetChange;
  /** Null on APPEARED and DISAPPEARED, which are about the asset itself. */
  previous_value: string | null;
  current_value: string | null;
  observed_at: string;
  scan_id: string | null;
  asset: {
    id: string;
    name: string;
    resource_type: string;
    environment: string | null;
    /**
     * Whether the asset is missing *now*, which is what turns a DISAPPEARED
     * row from history into something to act on.
     */
    absent_since: string | null;
  };
}

/**
 * Whether a connection reacts to change, and what the customer must run to
 * make it.
 *
 * The commands are the deliverable. CloudGuard cannot create the Event Grid
 * subscription itself — that is a write in the customer's tenant, and holding
 * no write permission anywhere is the strongest claim this product makes — so
 * it generates what the customer runs, one per subscription, because that is
 * how Event Grid is scoped.
 */
export interface ChangeEventSetup {
  enabled: boolean;
  /** Null when the API has no public base URL configured to deliver to. */
  webhook_url: string | null;
  /** Set while a burst of changes is settling and a scan is owed. */
  pending_since: string | null;
  last_event_at: string | null;
  quiet_period_minutes: number;
  minimum_interval_minutes: number;
  commands: { subscription_id: string; command: string }[];
}

/** What CloudGuard asks a customer to grant, shown before they grant it. */
export interface AzurePermissions {
  graph_application_permissions: string[];
  azure_rbac_role: string;
  access_type: string;
  writes_performed: string;
}

export type NotificationKind =
  | "REACHABLE_FINDING"
  | "VERIFIED_FIX"
  | "COVERAGE_DROP";

/**
 * One thing worth telling somebody, as it was true when it happened.
 *
 * `title` and `detail` come from the server already written. Composing them
 * here from a finding that has since been fixed would describe a state nobody
 * was ever notified about.
 */
export interface AppNotification {
  id: string;
  kind: NotificationKind;
  title: string;
  detail: string | null;
  /** A path, so the client routes it. Never an absolute URL. */
  link: string | null;
  /** When it happened, which is not when the row was written. */
  event_at: string;
}
