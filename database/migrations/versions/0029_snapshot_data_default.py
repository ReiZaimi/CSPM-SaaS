"""Stop a capture written as a manifest from also carrying an empty ``data``.

0001 created ``cloud_snapshots.data`` as ``jsonb NOT NULL DEFAULT '{}'::jsonb``.
0027 stopped writing the column and dropped its NOT NULL -- but left the
default. So every capture written since the flip got ``'{}'`` rather than NULL,
and the read path, which decides between the inline and manifest forms by
asking whether ``data`` is NULL, took the inline branch and rebuilt an estate
with nothing in it. Nothing failed at collection: the capture was stored, the
payloads were stored, the manifest was correct, and then ANALYZE raised
``KeyError: 'provider'`` on a capture whose only content was the default.

Two changes, and both are needed. The default goes, so a new capture written
without ``data`` is honestly NULL. And the rows already written that way are
set back to NULL -- guarded on ``manifest IS NOT NULL``, which names exactly
the captures written since 0027 and cannot touch a pre-0027 capture that
genuinely held an empty object.

``scanner._rebuild_capture`` stops asking the question this way round at the
same time: the manifest decides the form, because it is the thing that is
present in one form and absent in the other. A column with a default cannot
answer "did anybody write this".

Revision ID: 0029
Revises: 0028
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0029"
down_revision: str | None = "0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE cloud_snapshots ALTER COLUMN data DROP DEFAULT;")
    # Only captures that carry a manifest, and only where `data` is the empty
    # object the default supplied. A pre-0027 capture has no manifest and is
    # left exactly as it is, whatever it holds.
    op.execute(
        """
        UPDATE cloud_snapshots
           SET data = NULL
         WHERE manifest IS NOT NULL
           AND data = '{}'::jsonb;
        """
    )


def downgrade() -> None:
    # The rows set to NULL above are not restored: `'{}'` was never a capture,
    # and writing it back would recreate the bug rather than the state.
    op.execute(
        "ALTER TABLE cloud_snapshots ALTER COLUMN data SET DEFAULT '{}'::jsonb;"
    )
