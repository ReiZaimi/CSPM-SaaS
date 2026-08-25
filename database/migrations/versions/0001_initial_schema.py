"""Initial CloudGuard schema, with Row-Level Security as a real boundary.

Revision ID: 0001
Revises:
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


# Tenant-owned tables: RLS is enabled on every one of them, resolving through
# authenticated user -> organization_members -> organization_id -> row.
TENANT_TABLES = [
    "cloud_accounts",
    "cloud_resources",
    "resource_relationships",
    "scans",
    "cloud_snapshots",
    "scan_rule_results",
    "scan_evaluation_gaps",
    "findings",
    "risks",
    "risk_findings",
    "remediation_tasks",
    "exceptions",
    "audit_logs",
]

SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE SCHEMA IF NOT EXISTS app;
-- ---------------------------------------------------------------------------
-- Core tenancy
-- ---------------------------------------------------------------------------
CREATE TABLE organizations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        varchar(200) NOT NULL,
  slug        varchar(200) NOT NULL UNIQUE,
  industry    varchar(120),
  country     varchar(2),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_organizations_slug ON organizations (slug);

CREATE TABLE organization_members (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id         uuid NOT NULL,
  role            varchar(32) NOT NULL DEFAULT 'OWNER',
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_organization_members_organization_id UNIQUE (organization_id, user_id)
);
CREATE INDEX ix_organization_members_user_id ON organization_members (user_id);

-- ---------------------------------------------------------------------------
-- Cloud accounts. No client_id, no credential_reference, no customer secret --
-- CloudGuard authenticates as its own multi-tenant app (AZURE_INTEGRATION.md 2).
-- ---------------------------------------------------------------------------
CREATE TABLE cloud_accounts (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider             varchar(16) NOT NULL DEFAULT 'azure',
  account_name         varchar(200) NOT NULL,
  tenant_id            varchar(64) NOT NULL,
  subscription_id      varchar(64),
  consent_status       varchar(16) NOT NULL DEFAULT 'PENDING',
  consented_scopes     jsonb,
  consented_by_user_id uuid,
  consented_at         timestamptz,
  rbac_verified_at     timestamptz,
  status               varchar(16) NOT NULL DEFAULT 'PENDING',
  status_detail        text,
  last_scan_at         timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_cloud_accounts_organization_id
    UNIQUE (organization_id, provider, tenant_id, subscription_id)
);
CREATE INDEX ix_cloud_accounts_organization_id ON cloud_accounts (organization_id);

-- ---------------------------------------------------------------------------
-- Assets
-- ---------------------------------------------------------------------------
CREATE TABLE cloud_resources (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  cloud_account_id     uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  provider             varchar(16) NOT NULL,
  provider_resource_id varchar(1024) NOT NULL,
  resource_type        varchar(64) NOT NULL,
  name                 varchar(512) NOT NULL,
  region               varchar(64),
  environment          varchar(64),
  criticality          varchar(16) NOT NULL DEFAULT 'UNKNOWN',
  data_sensitivity     varchar(16) NOT NULL DEFAULT 'UNKNOWN',
  public_exposure      varchar(16) NOT NULL DEFAULT 'UNKNOWN',
  metadata             jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at        timestamptz NOT NULL DEFAULT now(),
  last_seen_at         timestamptz NOT NULL DEFAULT now(),
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_cloud_resources_cloud_account_id
    UNIQUE (cloud_account_id, provider_resource_id)
);
CREATE INDEX ix_cloud_resources_organization_id ON cloud_resources (organization_id);
CREATE INDEX ix_cloud_resources_org_type ON cloud_resources (organization_id, resource_type);

CREATE TABLE resource_relationships (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  source_resource_id  uuid NOT NULL REFERENCES cloud_resources(id) ON DELETE CASCADE,
  target_resource_id  uuid NOT NULL REFERENCES cloud_resources(id) ON DELETE CASCADE,
  relationship_type   varchar(32) NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_resource_relationships_edge
    UNIQUE (source_resource_id, target_resource_id, relationship_type)
);
CREATE INDEX ix_resource_relationships_organization_id
  ON resource_relationships (organization_id);

-- ---------------------------------------------------------------------------
-- Scans and snapshots. Every scan produces exactly one snapshot.
-- ---------------------------------------------------------------------------
CREATE TABLE scans (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id   uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  cloud_account_id  uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  status            varchar(24) NOT NULL DEFAULT 'QUEUED',
  started_at        timestamptz,
  completed_at      timestamptz,
  resource_count    integer NOT NULL DEFAULT 0,
  rule_count        integer NOT NULL DEFAULT 0,
  finding_count     integer NOT NULL DEFAULT 0,
  error_message     text,
  collection_errors jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_scans_organization_id ON scans (organization_id);
CREATE INDEX ix_scans_status ON scans (status);

CREATE TABLE cloud_snapshots (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  cloud_account_id uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  scan_id          uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  snapshot_version varchar(16) NOT NULL DEFAULT '1.0',
  data             jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_cloud_snapshots_scan_id UNIQUE (scan_id)
);
CREATE INDEX ix_cloud_snapshots_organization_id ON cloud_snapshots (organization_id);

CREATE TABLE scan_rule_results (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scan_id              uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  rule_id              varchar(32) NOT NULL,
  evaluated_count      integer NOT NULL DEFAULT 0,
  passed_count         integer NOT NULL DEFAULT 0,
  failed_count         integer NOT NULL DEFAULT 0,
  unknown_count        integer NOT NULL DEFAULT 0,
  not_applicable_count integer NOT NULL DEFAULT 0,
  created_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_scan_rule_results_scan_id UNIQUE (scan_id, rule_id)
);
CREATE INDEX ix_scan_rule_results_organization_id ON scan_rule_results (organization_id);

CREATE TABLE scan_evaluation_gaps (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scan_id         uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  rule_id         varchar(32) NOT NULL,
  resource_id     uuid REFERENCES cloud_resources(id) ON DELETE CASCADE,
  reason          text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_scan_evaluation_gaps_organization_id ON scan_evaluation_gaps (organization_id);
CREATE INDEX ix_scan_evaluation_gaps_scan_id ON scan_evaluation_gaps (scan_id);

-- ---------------------------------------------------------------------------
-- Rule catalogue. Global product data, not tenant-owned. Read-only mirror of
-- the Python registry -- authenticated users may SELECT and nothing else.
-- ---------------------------------------------------------------------------
CREATE TABLE rules (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id                  varchar(32) NOT NULL UNIQUE,
  name                     varchar(200) NOT NULL,
  description              text NOT NULL,
  category                 varchar(32) NOT NULL,
  provider                 varchar(16) NOT NULL,
  severity                 varchar(16) NOT NULL,
  version                  varchar(16) NOT NULL,
  exploitability           integer NOT NULL DEFAULT 0,
  scope                    varchar(16) NOT NULL,
  applies_to               jsonb NOT NULL DEFAULT '[]'::jsonb,
  enabled                  boolean NOT NULL DEFAULT true,
  remediation              text NOT NULL,
  estimated_effort_minutes integer NOT NULL DEFAULT 30,
  rationale                text NOT NULL DEFAULT '',
  compliance_mappings      jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at               timestamptz NOT NULL DEFAULT now(),
  updated_at               timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_rules_rule_id ON rules (rule_id);

-- ---------------------------------------------------------------------------
-- Findings, risks, remediation
-- ---------------------------------------------------------------------------
CREATE TABLE findings (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scan_id              uuid REFERENCES scans(id) ON DELETE SET NULL,
  rule_id              varchar(32) NOT NULL,
  resource_id          uuid REFERENCES cloud_resources(id) ON DELETE CASCADE,
  severity             varchar(16) NOT NULL,
  status               varchar(24) NOT NULL DEFAULT 'OPEN',
  title                varchar(400) NOT NULL,
  description          text NOT NULL,
  evidence             jsonb NOT NULL DEFAULT '{}'::jsonb,
  remediation          text NOT NULL DEFAULT '',
  rule_version         varchar(16) NOT NULL DEFAULT '1.0',
  risk_score           numeric(5,2),
  first_detected_at    timestamptz NOT NULL,
  last_detected_at     timestamptz NOT NULL,
  resolved_at          timestamptz,
  resolved_by_scan_id  uuid REFERENCES scans(id) ON DELETE SET NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_findings_org_rule_resource UNIQUE (organization_id, rule_id, resource_id)
);
CREATE INDEX ix_findings_organization_id ON findings (organization_id);
CREATE INDEX ix_findings_rule_id ON findings (rule_id);
CREATE INDEX ix_findings_org_status ON findings (organization_id, status);

CREATE TABLE risks (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id   uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  title             varchar(400) NOT NULL,
  description       text NOT NULL DEFAULT '',
  risk_score        numeric(5,2) NOT NULL DEFAULT 0,
  risk_level        varchar(16) NOT NULL DEFAULT 'LOW',
  status            varchar(16) NOT NULL DEFAULT 'OPEN',
  severity          varchar(16) NOT NULL,
  asset_criticality varchar(16) NOT NULL,
  data_sensitivity  varchar(16) NOT NULL,
  internet_exposure varchar(16) NOT NULL,
  exploitability    numeric(3,1) NOT NULL DEFAULT 0,
  business_impact   numeric(3,1) NOT NULL DEFAULT 0,
  score_breakdown   jsonb NOT NULL DEFAULT '{}'::jsonb,
  owner_id          uuid,
  due_date          date,
  resolved_at       timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_risks_organization_id ON risks (organization_id);
CREATE INDEX ix_risks_status ON risks (status);

CREATE TABLE risk_findings (
  risk_id         uuid NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
  finding_id      uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  PRIMARY KEY (risk_id, finding_id)
);
CREATE INDEX ix_risk_findings_organization_id ON risk_findings (organization_id);
CREATE INDEX ix_risk_findings_finding_id ON risk_findings (finding_id);

CREATE TABLE remediation_tasks (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id               uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  risk_id                  uuid REFERENCES risks(id) ON DELETE SET NULL,
  assigned_to              uuid,
  status                   varchar(16) NOT NULL DEFAULT 'TODO',
  priority                 varchar(16) NOT NULL DEFAULT 'MEDIUM',
  due_date                 date,
  estimated_effort_minutes integer NOT NULL DEFAULT 30,
  notes                    text,
  completed_at             timestamptz,
  created_at               timestamptz NOT NULL DEFAULT now(),
  updated_at               timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_remediation_tasks_organization_id ON remediation_tasks (organization_id);

CREATE TABLE exceptions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id      uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  approved_by     uuid NOT NULL,
  reason          text NOT NULL,
  expires_at      timestamptz,
  status          varchar(16) NOT NULL DEFAULT 'ACTIVE',
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_exceptions_organization_id ON exceptions (organization_id);

CREATE TABLE audit_logs (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id         uuid,
  action          varchar(64) NOT NULL,
  resource_type   varchar(64) NOT NULL,
  resource_id     uuid,
  metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip_address      inet,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_audit_logs_organization_id ON audit_logs (organization_id);
"""

# Defined after the tables: a LANGUAGE sql function body is parsed and its
# table references resolved at CREATE time, so these cannot come first.
FUNCTIONS_SQL = """
-- ---------------------------------------------------------------------------
-- Identity helpers
--
-- app.user_id() reads the same GUC Supabase's PostgREST sets, so one set of
-- policies works unchanged against local PostgreSQL and a real Supabase project.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.user_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(
    current_setting('request.jwt.claims', true)::jsonb ->> 'sub', ''
  )::uuid
$$;

-- SECURITY DEFINER so the membership lookup inside a policy does not re-enter
-- RLS on organization_members and recurse. This is why FORCE ROW LEVEL SECURITY
-- is deliberately NOT set: the application connects as a non-owner role
-- (cloudguard_app), so ownership exemption never applies to request traffic.
CREATE OR REPLACE FUNCTION app.is_member(p_org uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_members m
    WHERE m.organization_id = p_org
      AND m.user_id = app.user_id()
  )
$$;

CREATE OR REPLACE FUNCTION app.has_role(p_org uuid, p_roles text[]) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_members m
    WHERE m.organization_id = p_org
      AND m.user_id = app.user_id()
      AND m.role = ANY(p_roles)
  )
$$;
"""


# Creating an organization is a bootstrap problem: the creator is not yet a
# member, so no membership-based INSERT policy can authorize it. Rather than
# widen the policy (which would let anyone insert a membership into any org),
# the whole operation is one SECURITY DEFINER function that creates the org and
# the creator's OWNER membership atomically.
BOOTSTRAP_SQL = """
CREATE OR REPLACE FUNCTION app.create_organization(
  p_name     text,
  p_slug     text,
  p_industry text DEFAULT NULL,
  p_country  text DEFAULT NULL
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  v_user uuid := app.user_id();
  v_org  uuid;
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'not authenticated' USING ERRCODE = '28000';
  END IF;

  INSERT INTO public.organizations (name, slug, industry, country)
  VALUES (p_name, p_slug, p_industry, p_country)
  RETURNING id INTO v_org;

  INSERT INTO public.organization_members (organization_id, user_id, role)
  VALUES (v_org, v_user, 'OWNER');

  RETURN v_org;
END;
$$;
"""


def _policy_sql() -> str:
    stmts: list[str] = []

    # --- organizations: visible to members; never inserted directly ----------
    stmts.append("ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;")
    stmts.append(
        "CREATE POLICY org_select ON organizations FOR SELECT "
        "USING (app.is_member(id));"
    )
    stmts.append(
        "CREATE POLICY org_update ON organizations FOR UPDATE "
        "USING (app.has_role(id, ARRAY['OWNER','ADMIN'])) "
        "WITH CHECK (app.has_role(id, ARRAY['OWNER','ADMIN']));"
    )
    stmts.append(
        "CREATE POLICY org_delete ON organizations FOR DELETE "
        "USING (app.has_role(id, ARRAY['OWNER']));"
    )

    # --- organization_members ------------------------------------------------
    stmts.append("ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;")
    stmts.append(
        "CREATE POLICY member_select ON organization_members FOR SELECT "
        "USING (app.is_member(organization_id));"
    )
    # Only an existing OWNER/ADMIN may add or change members -- this is what
    # stops a user from inserting themselves into someone else's organization.
    stmts.append(
        "CREATE POLICY member_insert ON organization_members FOR INSERT "
        "WITH CHECK (app.has_role(organization_id, ARRAY['OWNER','ADMIN']));"
    )
    stmts.append(
        "CREATE POLICY member_update ON organization_members FOR UPDATE "
        "USING (app.has_role(organization_id, ARRAY['OWNER','ADMIN'])) "
        "WITH CHECK (app.has_role(organization_id, ARRAY['OWNER','ADMIN']));"
    )
    stmts.append(
        "CREATE POLICY member_delete ON organization_members FOR DELETE "
        "USING (app.has_role(organization_id, ARRAY['OWNER','ADMIN']));"
    )

    # --- every other tenant-owned table --------------------------------------
    # One uniform policy per table. Note the WITH CHECK on write: PostgreSQL
    # itself refuses a row written with someone else's organization_id, so a
    # bug in the service layer cannot produce cross-tenant data.
    for table in TENANT_TABLES:
        stmts.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        stmts.append(
            f"CREATE POLICY {table}_tenant_select ON {table} FOR SELECT "
            "USING (app.is_member(organization_id));"
        )
        stmts.append(
            f"CREATE POLICY {table}_tenant_insert ON {table} FOR INSERT "
            "WITH CHECK (app.is_member(organization_id));"
        )
        stmts.append(
            f"CREATE POLICY {table}_tenant_update ON {table} FOR UPDATE "
            "USING (app.is_member(organization_id)) "
            "WITH CHECK (app.is_member(organization_id));"
        )
        stmts.append(
            f"CREATE POLICY {table}_tenant_delete ON {table} FOR DELETE "
            "USING (app.is_member(organization_id));"
        )

    # --- rules: global catalogue, readable by all, writable by none -----------
    stmts.append("ALTER TABLE rules ENABLE ROW LEVEL SECURITY;")
    stmts.append("CREATE POLICY rules_read_all ON rules FOR SELECT USING (true);")

    return "\n".join(stmts)


GRANTS_SQL = """
-- The application role reaches the data only through `authenticated`, and only
-- through the policies above. It is granted no rights on the rules catalogue
-- beyond SELECT, so the read-mirror cannot be edited through the API.
GRANT USAGE ON SCHEMA public TO authenticated, anon;
GRANT USAGE ON SCHEMA app TO authenticated, anon;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authenticated;
REVOKE INSERT, UPDATE, DELETE ON rules FROM authenticated;
GRANT SELECT ON rules TO authenticated;

GRANT EXECUTE ON FUNCTION app.user_id() TO authenticated, anon;
GRANT EXECUTE ON FUNCTION app.is_member(uuid) TO authenticated, anon;
GRANT EXECUTE ON FUNCTION app.has_role(uuid, text[]) TO authenticated, anon;
GRANT EXECUTE ON FUNCTION app.create_organization(text, text, text, text) TO authenticated;
"""


def upgrade() -> None:
    op.execute(SCHEMA_SQL)
    op.execute(FUNCTIONS_SQL)
    op.execute(BOOTSTRAP_SQL)
    op.execute(_policy_sql())
    op.execute(GRANTS_SQL)


def downgrade() -> None:
    tables = [
        "audit_logs",
        "exceptions",
        "remediation_tasks",
        "risk_findings",
        "risks",
        "findings",
        "rules",
        "scan_evaluation_gaps",
        "scan_rule_results",
        "cloud_snapshots",
        "scans",
        "resource_relationships",
        "cloud_resources",
        "cloud_accounts",
        "organization_members",
        "organizations",
    ]
    for table in tables:
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE;")
    op.execute("DROP SCHEMA IF EXISTS app CASCADE;")
