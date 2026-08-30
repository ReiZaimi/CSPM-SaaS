"""A scan holds a lease, so an abandoned one stops blocking its connection.

Revision ID: 0009
Revises: 0008

A scan ran as one Celery task with no retries and no supervision. If the worker
was redeployed, ran out of memory, or was killed halfway, the row stayed in
``DISCOVERING`` for ever -- and ``scan_in_flight`` treats every non-terminal
status as a scan in progress, so the connection answered 409 to every attempt
to scan it again. There was no timeout, no operator endpoint and no recovery
path: the only way out was editing the database by hand.

``lease_until`` is the fix, and it is deliberately the smallest one that works.
A running scan holds a lease it extends as it makes progress, and a periodic
task fails any scan whose lease has expired. A worker that dies stops extending,
so the scan is reclaimed a few minutes later with a message saying what happened
rather than sitting silent for ever.

A queued scan carries no lease yet -- nothing has claimed it -- so it is judged
on ``created_at`` instead, with a much longer grace period. A queue can legitimately
be minutes deep behind a large tenant; a scan that has been queued for an hour is
a message nobody received.

The partial index is what the reaper reads. It covers only non-terminal scans,
which is a small fraction of the table and stays small as history grows.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

# Kept in sync with app.core.enums.ScanStatus.is_terminal. Listed rather than
# derived because a migration must describe the database at the moment it ran,
# not follow the application's later opinions.
NON_TERMINAL = "'QUEUED', 'DISCOVERING', 'NORMALIZING', 'EVALUATING', 'CALCULATING_RISK'"


def upgrade() -> None:
    op.execute("ALTER TABLE scans ADD COLUMN lease_until timestamptz;")
    op.execute(
        f"""
        CREATE INDEX ix_scans_active_lease
            ON scans (lease_until)
         WHERE status IN ({NON_TERMINAL});
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_scans_active_lease;")
    op.execute("ALTER TABLE scans DROP COLUMN lease_until;")
