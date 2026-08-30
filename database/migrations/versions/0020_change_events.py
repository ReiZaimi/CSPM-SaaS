"""Letting the environment say when it has changed.

Revision ID: 0020
Revises: 0019

A schedule is a promise about how stale the picture may get. It is not a promise
that the picture is right: a subscription scanned nightly is wrong from the
moment somebody opens a security group at nine in the morning until the scan at
three the next.

Event Grid closes that window, and CloudGuard cannot switch it on. Creating an
event subscription is a *write* in the customer's tenant, and holding no write
permission at all is the strongest security claim this product makes -- so the
customer creates it, from a command CloudGuard generates, exactly as they deploy
the scanner role.

Three columns, and the two timestamps are the debounce. A single deployment
emits dozens of ARM events in a minute; scanning on each would be a scan storm
against the customer's own API limits. The trigger waits for quiet instead, and
keeping *when the burst started* separate from *when the last event arrived*
means the scan that eventually runs knows how long the environment had been
drifting rather than only that it stopped.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE cloud_connections
            -- Off by default, like the schedule beside it. A customer's cloud
            -- is not turned into a source of inbound traffic without them
            -- asking for it.
            ADD COLUMN change_events_enabled boolean NOT NULL DEFAULT false,
            ADD COLUMN change_pending_since timestamptz,
            ADD COLUMN last_change_event_at timestamptz;
        """
    )
    # What the trigger sweep reads on every tick: connections with a burst
    # outstanding, which is a small fraction of the table and stays small.
    op.execute(
        """
        CREATE INDEX ix_cloud_connections_change_pending
            ON cloud_connections (change_pending_since)
         WHERE change_pending_since IS NOT NULL;
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_cloud_connections_change_pending;")
    op.execute(
        """
        ALTER TABLE cloud_connections
            DROP COLUMN IF EXISTS last_change_event_at,
            DROP COLUMN IF EXISTS change_pending_since,
            DROP COLUMN IF EXISTS change_events_enabled;
        """
    )
