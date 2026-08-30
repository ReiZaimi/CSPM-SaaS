"""A scan covers a connection, not a single subscription.

Revision ID: 0006
Revises: 0005

A connection discovers every subscription beneath it, and until now each one
was scanned separately: fifty subscriptions meant fifty scans, fifty snapshots
and fifty security scores, with no rule able to see across them. The scope of a
scan is now the connection, and the subscriptions beneath it are what it reads.

``scans.cloud_account_id`` becomes nullable rather than disappearing. The
single-subscription form still exists and is still how re-scanning one finding
works -- narrowing to the one subscription that finding lives in is the right
behaviour there, not a legacy path to be migrated away.

``cloud_snapshots`` loses its one-per-scan constraint and gains one per
(scan, subscription). Each subscription's payload stays a separate verbatim
record: merging them before storage would destroy the only property the
snapshot has, which is that it is what Azure actually said.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE scans
          ALTER COLUMN cloud_account_id DROP NOT NULL,
          ADD COLUMN connection_id uuid
              REFERENCES cloud_connections(id) ON DELETE CASCADE;
        """
    )
    op.execute(
        "CREATE INDEX ix_scans_connection_id ON scans (connection_id) "
        "WHERE connection_id IS NOT NULL;"
    )

    # Existing rows are single-subscription scans and stay that way: their
    # cloud_account_id is still set, so nothing about how they read changes.
    op.execute(
        """
        ALTER TABLE cloud_snapshots
          DROP CONSTRAINT IF EXISTS uq_cloud_snapshots_scan_id;
        """
    )
    op.execute(
        """
        ALTER TABLE cloud_snapshots
          ADD CONSTRAINT uq_cloud_snapshots_scan_account
          UNIQUE (scan_id, cloud_account_id);
        """
    )


def downgrade() -> None:
    # Refuses rather than silently discarding. A tenant-wide scan holds several
    # snapshots and reinstating one-per-scan would delete all but one of them,
    # which is data the customer's cloud may no longer be able to reproduce.
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM cloud_snapshots
            GROUP BY scan_id HAVING count(*) > 1
          ) THEN
            RAISE EXCEPTION
              'Cannot downgrade: some scans hold more than one snapshot. '
              'Delete the tenant-wide scans first.';
          END IF;
        END $$;
        """
    )
    op.execute(
        """
        ALTER TABLE cloud_snapshots
          DROP CONSTRAINT IF EXISTS uq_cloud_snapshots_scan_account;
        """
    )
    op.execute(
        """
        ALTER TABLE cloud_snapshots
          ADD CONSTRAINT uq_cloud_snapshots_scan_id UNIQUE (scan_id);
        """
    )
    op.execute("DROP INDEX IF EXISTS ix_scans_connection_id;")
    op.execute(
        """
        DELETE FROM scans WHERE cloud_account_id IS NULL;
        ALTER TABLE scans
          DROP COLUMN IF EXISTS connection_id,
          ALTER COLUMN cloud_account_id SET NOT NULL;
        """
    )
