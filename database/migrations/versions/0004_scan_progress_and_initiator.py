"""Scan progress, and who asked for it.

Revision ID: 0004
Revises: 0003

Three columns, each answering a question the scans page could not.

``triggered_by_user_id`` records who started a run. Scans were previously
anonymous, which is fine with one user and useless the moment a finding is
disputed -- "who ran this and when" is the first question asked and nothing
could answer it. Not a foreign key, for the same reason
``organization_members.user_id`` is not: the ``auth`` schema belongs to
Supabase and may sit outside this migration's reach.

``progress_done`` / ``progress_total`` let a running scan say how far along it
is. Status alone moves in five coarse jumps, so a large tenant sits on
"Discovering" for minutes looking indistinguishable from a stall -- which, as
of this week, is a thing that actually happens and had to be diagnosed by
reading Railway logs.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE scans
          ADD COLUMN triggered_by_user_id uuid,
          ADD COLUMN progress_done  integer NOT NULL DEFAULT 0,
          ADD COLUMN progress_total integer NOT NULL DEFAULT 0;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE scans
          DROP COLUMN IF EXISTS triggered_by_user_id,
          DROP COLUMN IF EXISTS progress_done,
          DROP COLUMN IF EXISTS progress_total;
        """
    )
