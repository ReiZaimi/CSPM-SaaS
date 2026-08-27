"""Tenant-scoped connections, with subscriptions discovered beneath them.

Revision ID: 0002
Revises: 0001

A cloud account used to *be* the connection: one row per subscription, its
tenant id typed in by hand. That had two problems this migration fixes.

The first is a blind spot. A subscription created after onboarding was invisible
to CloudGuard -- nobody had registered it -- and an environment that is never
scanned reports no findings, which reads as safe. For a posture product that is
the worst possible failure mode, and it was silent.

The second is a tenant-binding hole. ``cloud_accounts.tenant_id`` was NOT NULL
and came from the request body, while validation only checked whether Azure
answered. CloudGuard's service principal exists in every tenant that has ever
consented, so naming one of those tenants on a new connection and clicking
verify would succeed against someone else's environment. ``tenant_id`` on the
new table is nullable and written in exactly one place: the consent callback,
from what Entra itself reports.

Existing rows are adopted rather than discarded -- each becomes a
SUBSCRIPTION-scoped connection with itself as the single discovered child, so
no scan history, finding, or resource changes meaning.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


SCHEMA_SQL = """
CREATE TABLE cloud_connections (
  id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id             uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider                    varchar(16) NOT NULL DEFAULT 'azure',
  name                        varchar(200) NOT NULL,
  scope_type                  varchar(24) NOT NULL DEFAULT 'TENANT_ROOT',
  scope_id                    varchar(200),
  permission_mode             varchar(16) NOT NULL DEFAULT 'READER',
  role_version                varchar(16) NOT NULL DEFAULT 'v1',
  -- Nullable on purpose: written only by the consent callback, from the tenant
  -- Entra reports. Never accepted from a request body.
  tenant_id                   varchar(64),
  service_principal_object_id varchar(64),
  external_id                 varchar(64) NOT NULL,
  consent_status              varchar(16) NOT NULL DEFAULT 'PENDING',
  consented_scopes            jsonb,
  consented_by_user_id        uuid,
  consented_at                timestamptz,
  rbac_verified_at            timestamptz,
  external_id_verified        boolean NOT NULL DEFAULT false,
  status                      varchar(16) NOT NULL DEFAULT 'PENDING',
  status_detail               text,
  last_discovery_at           timestamptz,
  created_at                  timestamptz NOT NULL DEFAULT now(),
  updated_at                  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_cloud_connections_organization_id
    UNIQUE (organization_id, provider, tenant_id, scope_id)
);
CREATE INDEX ix_cloud_connections_organization_id ON cloud_connections (organization_id);
CREATE INDEX ix_cloud_connections_tenant_id ON cloud_connections (tenant_id);

ALTER TABLE cloud_accounts
  ADD COLUMN connection_id uuid REFERENCES cloud_connections(id) ON DELETE CASCADE,
  ADD COLUMN display_name  varchar(200),
  ADD COLUMN discovered_at timestamptz,
  ADD COLUMN in_scope      boolean NOT NULL DEFAULT true;

CREATE INDEX ix_cloud_accounts_connection_id ON cloud_accounts (connection_id);
"""

# Every pre-existing account becomes its own SUBSCRIPTION-scoped connection.
# gen_random_uuid() per row, so the mapping is done in one statement with the
# account id carried across rather than in a loop.
BACKFILL_SQL = """
INSERT INTO cloud_connections (
  id, organization_id, provider, name, scope_type, scope_id, permission_mode,
  role_version, tenant_id, external_id, consent_status, consented_scopes,
  consented_by_user_id, consented_at, rbac_verified_at, status, status_detail,
  created_at, updated_at
)
SELECT
  gen_random_uuid(), a.organization_id, a.provider, a.account_name,
  'SUBSCRIPTION', a.subscription_id, 'READER', 'v1', a.tenant_id,
  encode(gen_random_bytes(16), 'hex'), a.consent_status, a.consented_scopes,
  a.consented_by_user_id, a.consented_at, a.rbac_verified_at, a.status,
  a.status_detail, a.created_at, a.updated_at
FROM cloud_accounts a
WHERE a.connection_id IS NULL;

-- Re-link each account to the connection just created from it. Matching on the
-- tuple is safe because the old unique constraint guaranteed it was unique.
UPDATE cloud_accounts a
SET connection_id = c.id,
    display_name  = COALESCE(a.display_name, a.account_name),
    discovered_at = a.created_at
FROM cloud_connections c
WHERE a.connection_id IS NULL
  AND c.organization_id = a.organization_id
  AND c.provider        = a.provider
  AND c.tenant_id       = a.tenant_id
  AND c.scope_id IS NOT DISTINCT FROM a.subscription_id;

-- Discovery keys on (connection, subscription); the old constraint would block
-- two connections legitimately seeing the same subscription.
ALTER TABLE cloud_accounts DROP CONSTRAINT IF EXISTS uq_cloud_accounts_organization_id;
CREATE UNIQUE INDEX uq_cloud_accounts_connection_subscription
  ON cloud_accounts (connection_id, subscription_id);
"""

POLICY_SQL = """
ALTER TABLE cloud_connections ENABLE ROW LEVEL SECURITY;

CREATE POLICY cloud_connections_tenant_select ON cloud_connections FOR SELECT
  USING (app.is_member(organization_id));
CREATE POLICY cloud_connections_tenant_insert ON cloud_connections FOR INSERT
  WITH CHECK (app.is_member(organization_id));
CREATE POLICY cloud_connections_tenant_update ON cloud_connections FOR UPDATE
  USING (app.is_member(organization_id))
  WITH CHECK (app.is_member(organization_id));
CREATE POLICY cloud_connections_tenant_delete ON cloud_connections FOR DELETE
  USING (app.is_member(organization_id));

GRANT SELECT, INSERT, UPDATE, DELETE ON cloud_connections TO authenticated;
"""


def upgrade() -> None:
    op.execute(SCHEMA_SQL)
    op.execute(BACKFILL_SQL)
    op.execute(POLICY_SQL)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_cloud_accounts_connection_subscription;")
    op.execute(
        "ALTER TABLE cloud_accounts "
        "ADD CONSTRAINT uq_cloud_accounts_organization_id "
        "UNIQUE (organization_id, provider, tenant_id, subscription_id);"
    )
    op.execute(
        "ALTER TABLE cloud_accounts "
        "DROP COLUMN IF EXISTS connection_id, "
        "DROP COLUMN IF EXISTS display_name, "
        "DROP COLUMN IF EXISTS discovered_at, "
        "DROP COLUMN IF EXISTS in_scope;"
    )
    op.execute("DROP TABLE IF EXISTS cloud_connections CASCADE;")
