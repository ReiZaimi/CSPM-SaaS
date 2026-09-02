"""Band a risk reaches on established context alone.

Additive and nullable, with no backfill. NULL reads as "not computed" and the
score queries coalesce to ``risk_level``, so existing rows keep scoring exactly
as they did until the next scan rewrites them -- which is the same discipline
every other additive column here has followed: history is not rewritten by a
migration.

Revision ID: 0022
Revises: 0021
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE risks
            ADD COLUMN known_risk_level varchar(16);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE risks
            DROP COLUMN known_risk_level;
        """
    )
