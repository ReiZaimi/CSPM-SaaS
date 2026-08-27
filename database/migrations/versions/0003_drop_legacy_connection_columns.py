"""Drop columns removed by the Azure connector redesign.

Revision ID: 0003
Revises: 0002

The two-click onboarding redesign removed several columns from
cloud_connections that are no longer part of the model:

- permission_mode: always custom role now, no choice offered
- external_id: RBAC verification no longer uses an external id
- external_id_verified: replaced by rbac_verified_at
- consented_scopes: consent is all-or-nothing via admin consent
- consented_by_user_id: no longer tracked per connection
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE cloud_connections
            DROP COLUMN IF EXISTS permission_mode,
            DROP COLUMN IF EXISTS external_id,
            DROP COLUMN IF EXISTS external_id_verified,
            DROP COLUMN IF EXISTS consented_scopes,
            DROP COLUMN IF EXISTS consented_by_user_id;
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE cloud_connections
            ADD COLUMN IF NOT EXISTS permission_mode varchar(16) NOT NULL DEFAULT 'READER',
            ADD COLUMN IF NOT EXISTS external_id varchar(64) NOT NULL DEFAULT encode(gen_random_bytes(16), 'hex'),
            ADD COLUMN IF NOT EXISTS external_id_verified boolean NOT NULL DEFAULT false,
            ADD COLUMN IF NOT EXISTS consented_scopes jsonb,
            ADD COLUMN IF NOT EXISTS consented_by_user_id uuid;
    """)
