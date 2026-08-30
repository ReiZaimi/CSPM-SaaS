"""Scanning becomes continuous rather than something somebody remembers to do.

Revision ID: 0013
Revises: 0012

The product's first claim is continuous posture assessment, and every scan so
far has been a button press. A customer who connects Azure, scans once and gets
on with their week has a security report that ages silently: the environment
changes daily, and CloudGuard's picture of it does not.

``scan_interval_hours`` on the connection is the whole schedule. Not a cron
expression, deliberately -- "every night at 03:00" needs a timezone, a window
and an answer for what happens when a scan overruns its slot, and none of that
buys a customer anything a scanner can use. An interval says the true thing:
this environment is read at least this often.

``trigger`` on the scan says who asked. Before this there was one signal --
``triggered_by_user_id`` -- and a NULL in it was ambiguous the moment scans
could start themselves: an old manual scan whose user record had gone looked
exactly like a scheduled one. A column that states the answer is cheaper than a
convention that infers it.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE cloud_connections
            -- NULL means manual only, and it is the default: turning a
            -- customer's cloud into a recurring API cost without being asked
            -- would be a surprise on their Azure bill as much as on ours.
            ADD COLUMN scan_interval_hours integer,
            ADD CONSTRAINT ck_cloud_connections_scan_interval
                CHECK (scan_interval_hours IS NULL OR scan_interval_hours >= 1);
        """
    )
    op.execute(
        """
        ALTER TABLE scans
            ADD COLUMN trigger varchar(16) NOT NULL DEFAULT 'MANUAL';
        """
    )
    # What the scheduler reads on every tick: connections that want scanning,
    # which is a small fraction of the table and stays small.
    op.execute(
        """
        CREATE INDEX ix_cloud_connections_scheduled
            ON cloud_connections (organization_id)
         WHERE scan_interval_hours IS NOT NULL;
        """
    )
    # And how it works out whether one is due: the newest scan per connection.
    op.execute(
        """
        CREATE INDEX ix_scans_connection_created
            ON scans (connection_id, created_at DESC)
         WHERE connection_id IS NOT NULL;
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_scans_connection_created;")
    op.execute("DROP INDEX IF EXISTS ix_cloud_connections_scheduled;")
    op.execute("ALTER TABLE scans DROP COLUMN trigger;")
    op.execute(
        """
        ALTER TABLE cloud_connections
            DROP CONSTRAINT ck_cloud_connections_scan_interval,
            DROP COLUMN scan_interval_hours;
        """
    )
