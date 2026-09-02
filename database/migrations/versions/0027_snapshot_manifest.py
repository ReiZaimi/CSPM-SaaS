"""Stop storing every capture twice.

``cloud_snapshots.data`` held a whole capture per scan and was not deduplicated.
The per-key payloads in ``evidence_blobs`` hold the same bytes, split by
reading, content-addressed, and are. So a daily scan of an estate that has not
changed wrote one payload set and a fresh full capture every night.

A capture becomes a manifest: everything about the reading except the payloads,
plus the hashes of the payloads it was made of. Replay rebuilds the data by
merging those blobs, which ``TestCaptureReconstruction`` proves adds back up to
exactly what was stored.

``data`` is kept and made nullable rather than dropped. Captures written before
this have no manifest and must go on being replayable -- the read path takes
whichever it finds -- and dropping a column holding the only copy of anything is
not a migration anybody should be able to run by accident.

**This creates a dependency retention did not have.** A capture used to be
self-contained; now it points at blobs. ``prune_blobs`` refuses any hash a
retained manifest still names, or retention would destroy a capture inside its
own window. That interlock ships with this migration and is not optional.

Revision ID: 0027
Revises: 0026
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0027"
down_revision: str | None = "0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE cloud_snapshots
            ADD COLUMN manifest jsonb,
            ALTER COLUMN data DROP NOT NULL;
        """
    )
    # What the retention interlock asks: which hashes are still spoken for.
    op.execute(
        """
        CREATE INDEX ix_cloud_snapshots_manifest
            ON cloud_snapshots USING gin (manifest);
        """
    )


def downgrade() -> None:
    # `data` is left nullable. Reinstating NOT NULL would fail against any row
    # written while the manifest was in use, and a downgrade that cannot run is
    # worse than one that leaves a column more permissive than it found it.
    op.execute(
        """
        DROP INDEX IF EXISTS ix_cloud_snapshots_manifest;
        ALTER TABLE cloud_snapshots DROP COLUMN manifest;
        """
    )
