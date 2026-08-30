"""The directory is a reading of the tenant, not of a subscription.

Revision ID: 0008
Revises: 0007

Directory state -- users, roles, authentication methods -- was collected inside
the per-subscription plan, so a tenant-wide scan read it once per subscription.
Each read normalized into its own set of user resources, and ``cloud_resources``
is unique on (cloud_account_id, provider_resource_id), so the same administrator
became one row per subscription. Findings are identified by (organization, rule,
resource), which turned one administrator without MFA into one CRITICAL finding
per subscription -- for one person, one missing second factor.

The fix is to say what was always true: an asset belongs either to a
subscription or to the tenant, and directory assets belong to the tenant. Three
tables gain that distinction.

* ``cloud_resources``          -- account-scoped rows keep ``cloud_account_id``;
                                  directory rows carry ``connection_id`` instead.
* ``cloud_snapshots``          -- one capture per subscription, plus at most one
                                  directory capture per scan.
* ``scan_collection_results``  -- the coverage ledger follows the same split, so
                                  a directory task that failed is not reported
                                  against a subscription that is fine.

Exactly one of the two scopes is present on every row, enforced by a CHECK
rather than by convention. PostgreSQL treats NULLs as distinct in a unique
constraint, so each table also gains a partial unique index covering the rows
the existing constraint stopped bounding.

Existing rows are all account-scoped -- there was no other kind -- so the
backfill is to set ``connection_id`` from the account each row already points
at, and nothing needs deleting. The duplicate user rows earlier scans wrote are
left alone: they are what those scans saw, and the next scan reconciles them by
writing one directory-scoped row and letting the stale per-account ones age out
of ``last_seen_at``.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    # --- cloud_resources ---------------------------------------------------
    op.execute(
        """
        ALTER TABLE cloud_resources
            ALTER COLUMN cloud_account_id DROP NOT NULL,
            ADD COLUMN connection_id uuid
                REFERENCES cloud_connections(id) ON DELETE CASCADE;
        """
    )
    op.execute(
        """
        UPDATE cloud_resources r
           SET connection_id = a.connection_id
          FROM cloud_accounts a
         WHERE a.id = r.cloud_account_id;
        """
    )
    op.execute(
        """
        CREATE INDEX ix_cloud_resources_connection_id
            ON cloud_resources (connection_id);
        """
    )
    # The identity of a directory-scoped asset. Its account column is NULL, so
    # the table's existing unique constraint does not constrain it at all.
    op.execute(
        """
        CREATE UNIQUE INDEX uq_cloud_resources_directory_asset
            ON cloud_resources (connection_id, provider_resource_id)
         WHERE cloud_account_id IS NULL;
        """
    )
    op.execute(
        """
        ALTER TABLE cloud_resources
            ADD CONSTRAINT ck_cloud_resources_one_scope
            CHECK (
                (cloud_account_id IS NOT NULL)
                OR (cloud_account_id IS NULL AND connection_id IS NOT NULL)
            );
        """
    )

    # --- cloud_snapshots ---------------------------------------------------
    op.execute(
        """
        ALTER TABLE cloud_snapshots
            ALTER COLUMN cloud_account_id DROP NOT NULL,
            ADD COLUMN connection_id uuid
                REFERENCES cloud_connections(id) ON DELETE CASCADE;
        """
    )
    op.execute(
        """
        UPDATE cloud_snapshots s
           SET connection_id = a.connection_id
          FROM cloud_accounts a
         WHERE a.id = s.cloud_account_id;
        """
    )
    # A scan captures the directory at most once. Without this the NULL-account
    # rows would be unconstrained and a retried collection step could write a
    # second one, leaving replay two directories to choose between.
    op.execute(
        """
        CREATE UNIQUE INDEX uq_cloud_snapshots_scan_directory
            ON cloud_snapshots (scan_id)
         WHERE cloud_account_id IS NULL;
        """
    )
    op.execute(
        """
        ALTER TABLE cloud_snapshots
            ADD CONSTRAINT ck_cloud_snapshots_one_scope
            CHECK (
                (cloud_account_id IS NOT NULL)
                OR (cloud_account_id IS NULL AND connection_id IS NOT NULL)
            );
        """
    )

    # --- scan_collection_results -------------------------------------------
    op.execute(
        """
        ALTER TABLE scan_collection_results
            ALTER COLUMN cloud_account_id DROP NOT NULL,
            ADD COLUMN connection_id uuid
                REFERENCES cloud_connections(id) ON DELETE CASCADE;
        """
    )
    op.execute(
        """
        UPDATE scan_collection_results r
           SET connection_id = a.connection_id
          FROM cloud_accounts a
         WHERE a.id = r.cloud_account_id;
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX uq_scan_collection_directory_task
            ON scan_collection_results (scan_id, task_key)
         WHERE cloud_account_id IS NULL;
        """
    )
    op.execute(
        """
        ALTER TABLE scan_collection_results
            ADD CONSTRAINT ck_scan_collection_one_scope
            CHECK (
                (cloud_account_id IS NOT NULL)
                OR (cloud_account_id IS NULL AND connection_id IS NOT NULL)
            );
        """
    )


def downgrade() -> None:
    # Directory-scoped rows have no subscription to fall back to, so reversing
    # this means discarding them. That is the honest downgrade: the column they
    # need is going away, and inventing an account for them would leave rows
    # claiming a subscription they were never read from.
    op.execute("DELETE FROM scan_collection_results WHERE cloud_account_id IS NULL;")
    op.execute("DELETE FROM cloud_snapshots WHERE cloud_account_id IS NULL;")
    op.execute("DELETE FROM cloud_resources WHERE cloud_account_id IS NULL;")

    op.execute(
        """
        ALTER TABLE scan_collection_results
            DROP CONSTRAINT ck_scan_collection_one_scope,
            DROP COLUMN connection_id,
            ALTER COLUMN cloud_account_id SET NOT NULL;
        """
    )
    op.execute("DROP INDEX IF EXISTS uq_scan_collection_directory_task;")

    op.execute(
        """
        ALTER TABLE cloud_snapshots
            DROP CONSTRAINT ck_cloud_snapshots_one_scope,
            DROP COLUMN connection_id,
            ALTER COLUMN cloud_account_id SET NOT NULL;
        """
    )
    op.execute("DROP INDEX IF EXISTS uq_cloud_snapshots_scan_directory;")

    op.execute(
        """
        ALTER TABLE cloud_resources
            DROP CONSTRAINT ck_cloud_resources_one_scope,
            DROP COLUMN connection_id,
            ALTER COLUMN cloud_account_id SET NOT NULL;
        """
    )
    op.execute("DROP INDEX IF EXISTS uq_cloud_resources_directory_asset;")
    op.execute("DROP INDEX IF EXISTS ix_cloud_resources_connection_id;")
