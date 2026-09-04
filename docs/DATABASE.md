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
  provider_ref              JSONB -- mirrors the connection's; empty for Azure
  status, last_scan_at, created_at, updated_at
```

---

## 3. Resources, Scans, Snapshots

```
cloud_resources
  id, organization_id, cloud_account_id, connection_id, provider
  provider_resource_id
  resource_type, name, region, environment, criticality, data_sensitivity
  public_exposure, resource_metadata JSONB, first_seen_at, last_seen_at
  absent_since              -- set when a reading no longer contains it; the
                            -- asset is kept, not deleted, so a disappearance is
                            -- a change with a date rather than a silent gap
  criticality_source        -- NONE / INFERRED / TYPE_FLOOR / PROVIDER_TAG /
  data_sensitivity_source   -- INHERITED / CUSTOMER. Provenance travels with the
  environment_source        -- value: a CRITICAL somebody typed and one guessed
                            -- from a resource name multiply a finding
                            -- identically, and only one is worth arguing with
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
  id, organization_id, cloud_account_id, connection_id, scan_id
  snapshot_version, created_at
  manifest JSONB             -- everything the capture recorded except the
                             -- payloads, plus payload_hashes: the content hash
                             -- of each reading. The bytes live once in
                             -- evidence_blobs; holding them here as well meant
                             -- a nightly scan of an unchanged estate stored a
                             -- fresh full copy every night (DECISIONS.md §54)
  data JSONB                 -- nullable. Captures written before the manifest
                             -- carry their payloads inline and stay replayable
```

---

## 4. Rules, Findings, Coverage — extended for the finalized rule/risk engine

```
rules
  id, rule_id, name, description, category, provider, severity, version
  exploitability            -- 0-5, feeds the risk formula. A *ceiling*, not a
                            -- constant: a rule may return a lower value where
                            -- the evidence shows one instance is milder than
                            -- the worst case, and an observed compensating
                            -- control lowers it again. Never raised
                            -- (DECISIONS.md §47, §48)
  enabled, remediation, compliance_mappings JSONB, created_at, updated_at
  -- synced from the Python rule registry at startup/deploy; not independently
  -- editable via the DB in MVP

findings
  id, organization_id, scan_id, rule_id, resource_id
  severity, status, title, description, evidence JSONB, remediation TEXT
  rule_version               -- stamped at creation, for traceability (new)
  risk_score
  first_detected_at, last_detected_at, resolved_at, created_at, updated_at
  resolved_by_scan_id        -- which reading closed it, so "verified fixed" names
                             -- the evidence rather than asserting itself
  -- status: OPEN / IN_PROGRESS / RESOLVED / ACCEPTED_RISK / FALSE_POSITIVE
  -- RESOLVED is set automatically by a rescan that returns PASS, not manually
  -- `evidence` also carries `compensating_controls` where a rule observed a
  -- defence standing in front of the finding: it lowers the score and never
  -- closes it (RULE_ENGINE.md)

finding_events             -- the finding's own history: OPENED / REOPENED /
  id, organization_id, finding_id, scan_id     -- RESOLVED, with the scan that
  event, previous_status, current_status       -- observed each transition
  detail, observed_at

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
  id, organization_id, kind, title, description, severity, status
  risk_score, risk_level
  known_risk_level           -- the band over context CloudGuard *established*,
                             -- with every UNKNOWN input taken at the bottom of
                             -- the scale. risk_level ranks; this one is what the
                             -- org security score charges for, so a posture
                             -- number is never moved by CloudGuard's own blind
                             -- spots (RISK_ENGINE.md §3). NULL for scenarios
  asset_criticality, data_sensitivity, internet_exposure, exploitability
  business_impact            -- computed, not manually set (see RISK_ENGINE.md)
  score_breakdown JSONB      -- every component's value, weight and contribution,
                             -- so "why is this 71?" is answerable without
                             -- re-running anything
  scenario_key               -- stable identity of a route across scans; NULL for
  path JSONB                 -- FINDING risks. `path` is the route's steps
  observed_scan_id           -- which reading a route was last seen in. Set on
                             -- scenario risks and rewritten on every
                             -- observation, because the useful question about a
                             -- route is not when it appeared but whether
                             -- anything has looked since. SET NULL on a pruned
                             -- scan: risks outlive scans, as findings do
  owner_id, due_date, resolved_at, created_at, updated_at
  -- kind: FINDING / ATTACK_PATH / ESCALATION. A scenario risk is several
  --       findings seen as one route and is scored by a different formula
  --       (worst member + a bounded amplifier), never by the six weights

risk_findings
  risk_id, finding_id, organization_id
  -- Genuinely many-to-many now, not 1:1. A rule declaring `risk_grouping`
  -- collapses its findings into one risk with many members: the findings stay
  -- per resource because each is separately fixed and verified, while the risk
  -- layer stops repeating one sentence and stops charging the security score
  -- once per repetition. A scenario risk links the findings along its route.

risk_history                 -- one row per posture reading, for the trend line
  id, organization_id, scan_id, observed_at, security_score
  open_finding_count, findings_by_severity JSONB, risk_bands JSONB
  attack_path_count, created_at

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

## 6. Connections, Evidence, Verification, Change

Everything below post-dates the original schema draft. Grouped here rather than
folded into the sections above because each answers a question the first draft
did not ask.

```
cloud_connections          -- supersedes `cloud_accounts` as the unit a scan
  id, organization_id, provider, name          -- runs against. A connection is
  scope_type, scope_id                          -- one grant over one scope, so a
  tenant_id, service_principal_object_id        -- customer with a directory
  role_version                                  -- grant and three subscription
  consent_status, consented_at, rbac_verified_at    -- grants has four rows, each
  status, status_detail, last_discovery_at          -- separately consentable and
  scan_interval_hours        -- automatic scanning, off by default              -- separately revocable
  change_events_enabled, change_pending_since, last_change_event_at
  provider_ref JSONB         -- what only one provider has a word for: the AWS
                             -- scanner role's ARN and the external id its trust
                             -- policy must require. A blob rather than columns
                             -- because nothing neutral reads it -- tenant_id and
                             -- scope_id are columns precisely because the
                             -- scanner, the scheduler and the UI do. Holds no
                             -- customer secret and must not start to
                             -- (DECISIONS.md §70, migration 0034)
  -- scope_type is one enum across all three clouds, named in each one's own
  -- words: TENANT_ROOT / MANAGEMENT_GROUP / SUBSCRIPTION on Azure,
  -- ORGANIZATION / ORGANIZATIONAL_UNIT / ACCOUNT on AWS
  -- role_version is read back from Azure rather than only stamped at creation.
  -- It records which role is *assigned*, resolved from the actions on the
  -- definitions the scanner's principal holds -- so redeploying the role
  -- clears the "behind" prompt, which a column written once never could
  -- (DECISIONS.md §65)

context_declarations       -- what a person said, which beats anything inferred
  id, organization_id, cloud_account_id
  environment, criticality, data_sensitivity, note
  declared_by_user_id, declared_at
  -- UNKNOWN is not storable here: it is CloudGuard's word for "nothing said
  -- anything", so unsetting a field withdraws a claim rather than making one

rules                      -- read-mirror of the Python registry, global
  ...                       -- (not tenant-owned); synced at startup
  compliance_mappings JSONB  -- framework -> [control ids]
  requires_evidence JSONB    -- the evidence keys this rule reads, mirrored so
                             -- the compliance view can follow a control back to
                             -- the provider call behind it without importing
                             -- rule code. A rule deleted from the registry
                             -- keeps its row, disabled, so the controls it
                             -- answered for keep their history (migration 0032)

evidence                   -- per scan, per evidence key: did this listing
  id, organization_id, scan_id, cloud_account_id, connection_id    -- actually
  provider, evidence_key, category, outcome, detail                 -- arrive?
  item_count, collected_at
  region                     -- which region this was a reading of, for a
                             -- provider that reads per region. NULL means the
                             -- listing is global: every Azure row, and on AWS
                             -- IAM, S3 and Organizations. Beside evidence_key
                             -- rather than folded into it, because a rule
                             -- depends on the key -- seventeen rows here are
                             -- one answer to "did we see the security groups"
                             -- (DECISIONS.md §69, migration 0033)
  source_scan_id             -- which scan read the provider, where that is not
                             -- scan_id. A reading inside its reuse window is
                             -- carried into the next scan, which writes a row
                             -- of its own holding the original collected_at --
                             -- so the age survived and the authorship did not,
                             -- and finding_evidence.source_scan_id was copied
                             -- from scan_id, which could only name the scan
                             -- that reused it. NULL means this row *is* the
                             -- reading. No foreign key: provenance outlives the
                             -- scan it points at (DECISIONS.md §65)
  permissions JSONB          -- the actions the read was made under
  endpoints JSONB            -- [{path, api_version}]: what it called, and the
                             -- contract it called under. A response's shape is
                             -- a function of its api-version, so a field absent
                             -- from a capture is a setting nobody set *or* a
                             -- contract too old to return it -- and only the
                             -- second is CloudGuard's own staleness
  -- The row that makes UNKNOWN honest. A rule declares the keys it reads and
  -- degrades only when one of *those* failed -- not when a sibling listing in
  -- the same category did (RULE_ENGINE.md)
  -- UNIQUE NULLS NOT DISTINCT (scan_id, cloud_account_id, evidence_key,
  -- region). Both nullable columns mean "not scoped that way", so two unscoped
  -- readings are the same reading; under Postgres's default their NULLs would
  -- be distinct and the constraint would protect nothing

evidence_blobs             -- the verbatim JSON, deduplicated by content hash
  organization_id, content_hash        -- (both) the primary key
  payload_compressed BYTEA   -- the canonical bytes the hash was taken over,
                             -- zlib-compressed. Not JSONB: nothing ever queried
                             -- into it, a payload is read whole or not at all,
                             -- and JSONB stores a listing of 500 near-identical
                             -- objects as a parsed tree holding the key names
                             -- per value (DECISIONS.md §55)
  payload JSONB              -- nullable. Payloads stored before compression;
                             -- read as a fallback, no backfill
  byte_size, stored_bytes    -- what the reading was, and what keeping it costs
  first_stored_at, last_seen_at
  -- A CHECK requires one payload form or the other. "the bytes are gone" must
  -- never be readable as "the reading was empty" -- a subscription with no
  -- storage accounts produces a genuinely empty payload
  -- Retention measures from last_seen_at, not first_stored_at: an estate that
  -- has not changed in six months keeps one copy alive by re-reading it, and
  -- pruning on first storage would delete the payload behind every current
  -- reading. Pruning one invalidates no citation -- finding_evidence copies the
  -- hash rather than holding a key, so the record of what was read outlives the
  -- bytes (DECISIONS.md §51)
  -- Content-addressed because an estate that did not change between two scans
  -- stores one copy, not two, and re-evaluation needs the bytes intact

scan_steps                 -- a scan is resumable work, not one long call
  id, organization_id, scan_id, kind, cloud_account_id
  status, attempt, max_attempts, lease_until, worker_id
  error, started_at, finished_at, created_at
  -- `attempt` is the fence as well as the counter. A claim raises it, and every
  -- write a running step makes -- each lease renewal, and the settle at the end
  -- -- is conditional on the row still carrying the number it was claimed
  -- under. A worker paused past its lease has not died: unfenced, it came back
  -- and settled a step another worker was in the middle of, and ANALYZE (which
  -- waits on collection *settling*) then read a subscription still being
  -- written (DECISIONS.md §65)

remediation_verifications  -- did the fix actually hold?
  id, organization_id, finding_id, remediation_task_id
  rule_id, resource_id, cloud_account_id, connection_id
  status, claimed_at, claimed_by_user_id
  attempts, last_attempt_at, next_attempt_at
  last_state, observed_failure, detail, expected_state
  verified_by_scan_id, settled_at
  -- Marking work done does not close a finding; a scan does. This table is the
  -- gap between the two claims

asset_change_events        -- what moved between two readings of one environment
  id, organization_id, ...  -- APPEARED / DISAPPEARED / attribute moves, with
                            -- direction where a level went up or down. A move
                            -- into UNKNOWN has no direction
```

---

## 7. Row-Level Security

RLS is enabled on **every tenant-owned table**. Policies resolve through:

```
authenticated user → organization_members → organization_id → requested row
```

Never a bare `WHERE organization_id = request.organization_id` trusted from the client — RLS is a database-level boundary independent of application logic. Automated RLS tests confirm Organization A can never read Organization B's rows (see `TESTING.md`).

Supabase's own guidance is explicit that RLS should be treated as a real security boundary (with grants + policies), and that service-role/secret keys bypass RLS and must remain server-side — that principle governs credential handling throughout, not just this table set.
