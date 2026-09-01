"""When a subscription was last taken out of scope, or put back.

Revision ID: 0021
Revises: 0020

Unticking a subscription is the one destructive-looking act on the connections
screen: findings for it stop being produced, and the customer is told they are
kept and marked out of scope rather than deleted. Months later the only record
of that decision was a boolean, so the screen could say *that* a subscription
was excluded and never *when* -- which is the difference between "somebody
decided this in August" and "this has been silently unscanned for as long as
anyone can remember".

One nullable column. Rows that predate it keep NULL, which reads as "not since
CloudGuard started recording", and no backfill invents a date nobody chose.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE cloud_accounts
            ADD COLUMN scope_changed_at timestamptz;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE cloud_accounts
            DROP COLUMN IF EXISTS scope_changed_at;
        """
    )
