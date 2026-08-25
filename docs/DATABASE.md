# CloudGuard — Database Schema

All tables use UUID primary keys, timestamps, foreign keys, and RLS. Corrections made during design discussion are called out inline — treat this file as authoritative over any earlier draft.

---

## 1. Core Tables

```
organizations
  id, name, slug, industry, country, created_at, updated_at

organization_members
  id, organization_id, user_id, role, created_at, updated_at
  UNIQUE(organization_id, user_id)
```

---

## 2. cloud_accounts — corrected for the admin-consent auth model

The original build spec's `client_id`/`credential_reference` columns assumed a manual service-principal flow. Corrected to match the chosen auth model (`AZURE_INTEGRATION.md` §2) — **no per-customer secret is stored at all**:

```
cloud_accounts
  id, organization_id, provider, account_name
  tenant_id                -- customer's Entra directory ID
  subscription_id          -- (or a child table for multiple subscriptions)
  consent_status            -- PENDING / GRANTED / REVOKED
  consented_scopes          JSONB
  consented_by_user_id
  rbac_verified_at          -- Reader role confirmed via a live test call
  status, last_scan_at, created_at, updated_at
```

---

## 3. Resources, Scans, Snapshots

```
cloud_resources
  id, organization_id, cloud_account_id, provider, provider_resource_id
  resource_type, name, region, environment, criticality, data_sensitivity
  public_exposure, metadata JSONB, first_seen_at, last_seen_at
  created_at, updated_at

resource_relationships
  id, organization_id, source_resource_id, target_resource_id
  relationship_type, created_at

scans
  id, organization_id, cloud_account_id, status
  started_at, completed_at, resource_count, rule_count, finding_count
  error_message, created_at
  -- status: QUEUED / DISCOVERING / NORMALIZING / EVALUATING / CALCULATING_RISK
  --         / COMPLETED / FAILED / PARTIAL / CANCELLED

cloud_snapshots
  id, organization_id, cloud_account_id, scan_id
  snapshot_version, data JSONB, created_at
```

---

## 4. Rules, Findings, Coverage — extended for the finalized rule/risk engine

```
rules
  id, rule_id, name, description, category, provider, severity, version
  exploitability            -- 0-5, static, feeds the risk formula (new)
  enabled, remediation, compliance_mappings JSONB, created_at, updated_at
  -- synced from the Python rule registry at startup/deploy; not independently
  -- editable via the DB in MVP

findings
  id, organization_id, scan_id, rule_id, resource_id
  severity, status, title, description, evidence JSONB, remediation TEXT
  rule_version               -- stamped at creation, for traceability (new)
  risk_score
  first_detected_at, last_detected_at, resolved_at, created_at, updated_at
  -- status: OPEN / IN_PROGRESS / RESOLVED / ACCEPTED_RISK / FALSE_POSITIVE
  -- RESOLVED is set automatically by a rescan that returns PASS, not manually

scan_rule_results          -- coverage aggregate, one row per (scan_id, rule_id) (new)
  id, scan_id, rule_id
  evaluated_count, passed_count, failed_count, unknown_count, not_applicable_count
  created_at

scan_evaluation_gaps       -- per-resource UNKNOWN detail, backs the coverage
  id, scan_id, rule_id, resource_id      -- indicator; resource_id null for (new)
  reason                                  -- AGGREGATE-scope rules
  created_at
```

---

## 5. Risk & Remediation

```
risks
  id, organization_id, title, description, risk_score, risk_level, status
  asset_criticality, data_sensitivity, internet_exposure, exploitability
  business_impact            -- computed, not manually set (see RISK_ENGINE.md)
  owner_id, due_date, created_at, updated_at

risk_findings
  risk_id, finding_id        -- 1:1 for MVP; table supports future grouping

remediation_tasks
  id, organization_id, finding_id, risk_id, assigned_to, status, priority
  due_date, estimated_effort_minutes, notes
  created_at, updated_at, completed_at

exceptions
  id, organization_id, finding_id, approved_by, reason, expires_at, status, created_at

audit_logs
  id, organization_id, user_id, action, resource_type, resource_id
  metadata JSONB, ip_address, created_at
```

---

## 6. Row-Level Security

RLS is enabled on **every tenant-owned table**. Policies resolve through:

```
authenticated user → organization_members → organization_id → requested row
```

Never a bare `WHERE organization_id = request.organization_id` trusted from the client — RLS is a database-level boundary independent of application logic. Automated RLS tests confirm Organization A can never read Organization B's rows (see `TESTING.md`).

Supabase's own guidance is explicit that RLS should be treated as a real security boundary (with grants + policies), and that service-role/secret keys bypass RLS and must remain server-side — that principle governs credential handling throughout, not just this table set.
