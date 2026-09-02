"""Store a payload's bytes compressed instead of as a parsed JSONB tree.

``evidence_blobs.payload`` was JSONB, which is the wrong shape for what these
rows hold. A payload is a provider listing -- five hundred near-identical
objects repeating the same twenty key names and the same resource-group prefix
on every id -- and JSONB stores that as a parsed tree with the keys held per
value. PostgreSQL's TOAST compression only engages above a couple of kilobytes,
and by then the expensive representation has already been chosen.

Nothing ever queried into the column. A payload is read whole, by hash, in
``_rebuild_capture`` and in the evidence planner, or not at all -- so giving up
JSONB operators on it costs nothing that was being used. It is now the same
canonical bytes the content hash was taken over, run through zlib: on Azure
listings roughly a tenth of the size, and checkable against the hash it is filed
under, which a re-serialized tree would not have been.

``payload`` is kept and made nullable rather than dropped, and no backfill runs
here. Rewriting every historical payload is a long write on the largest table in
the schema, and it is not needed: the read path takes whichever form it finds,
and retention retires the old rows on its own schedule. What this does add is a
CHECK that a row holds one form or the other, so "the bytes are gone" can never
be mistaken for "the reading was empty" -- an empty payload is a real thing a
subscription with no storage accounts produces.

``stored_bytes`` records what a row costs to keep, next to ``byte_size``, which
goes on meaning what the reading was. Recorded rather than derived, because for
a not-yet-rewritten row the honest answer is not the length of a column that is
NULL.

Revision ID: 0028
Revises: 0027
"""

import zlib
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0028"
down_revision: str | None = "0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE evidence_blobs
            ADD COLUMN payload_compressed bytea,
            ADD COLUMN stored_bytes integer NOT NULL DEFAULT 0,
            ALTER COLUMN payload DROP NOT NULL;
        """
    )
    # Existing rows keep their JSONB payload, so the constraint holds for them
    # from the moment it is added. NOT VALID would be the careful move on a
    # constraint that might not hold; this one provably does, and validating it
    # now means the guarantee is real rather than aspirational.
    op.execute(
        """
        ALTER TABLE evidence_blobs
            ADD CONSTRAINT ck_evidence_blobs_payload_present
            CHECK (payload IS NOT NULL OR payload_compressed IS NOT NULL);
        """
    )


def downgrade() -> None:
    # Rows written after the upgrade hold their payload only in the compressed
    # column, so this inflates them back into `payload` before dropping it. A
    # downgrade that silently discarded them would destroy the only copy of
    # every reading taken while compression was in use.
    #
    # Done in Python rather than in SQL because PostgreSQL ships no zlib
    # inflate: `pg_column_compression` reports how a value is TOASTed and there
    # is nothing that undoes an application-level `zlib.compress`. So the rows
    # come back a page at a time -- these are the largest rows in the schema and
    # a single `SELECT` of all of them is how a downgrade runs a database out of
    # memory.
    connection = op.get_bind()
    while True:
        rows = connection.execute(
            sa.text(
                """
                SELECT organization_id, content_hash, payload_compressed
                  FROM evidence_blobs
                 WHERE payload IS NULL
                   AND payload_compressed IS NOT NULL
                 LIMIT 200
                """
            )
        ).all()
        if not rows:
            break
        for organization_id, content_hash, compressed in rows:
            connection.execute(
                sa.text(
                    """
                    UPDATE evidence_blobs
                       SET payload = CAST(:payload AS jsonb)
                     WHERE organization_id = :organization_id
                       AND content_hash = :content_hash
                    """
                ),
                {
                    # The stored bytes are the canonical JSON encoding, so they
                    # go back as they came: decoded, not re-serialized.
                    "payload": zlib.decompress(compressed).decode(),
                    "organization_id": organization_id,
                    "content_hash": content_hash,
                },
            )

    op.execute(
        """
        ALTER TABLE evidence_blobs
            DROP CONSTRAINT IF EXISTS ck_evidence_blobs_payload_present,
            DROP COLUMN payload_compressed,
            DROP COLUMN stored_bytes;
        """
    )
    # `payload` is left nullable. Reinstating NOT NULL would fail on any row the
    # inflate above could not recover, and a downgrade that cannot run is worse
    # than one that leaves a column more permissive than it found it.
