"""Evidence becomes a thing with an identity, provenance and one stored copy.

Revision ID: 0010
Revises: 0009

Two problems, one shape.

**Nothing could be traced to what produced it.** A finding pointed at a scan,
and a scan pointed at a single JSONB blob holding every listing it had read.
"Where did this come from" was answerable only by a person opening the blob and
reading it. The coverage ledger recorded that a listing had failed, but nothing
recorded that a listing had *succeeded* and what it cost to read -- which
permission, at what moment, and whether the bytes are still the same bytes.

**And every scan stored the whole environment again.** A customer scanning
daily whose network security groups have not changed in a month stored thirty
identical copies of them, inside thirty rows nothing prunes.

``scan_collection_results`` was already one row per (scan, scope, listing),
which is exactly the grain evidence wants. So it is renamed rather than
duplicated -- a second table at the same grain would be the parallel state this
migration exists to remove -- and gains what it was missing: what produced the
evidence, when, under which permissions, and a content hash pointing at one
stored copy of the payload.

``evidence_blobs`` holds those copies, keyed by (organization, content hash).
Scoped per organization deliberately. Content-addressed storage shared across
tenants would deduplicate correctly and still be wrong: whether a write finds an
existing row is observable, so a shared table lets one tenant learn that another
holds identical bytes. Within a tenant the dedup is where nearly all the saving
is anyway -- the same environment, read again tomorrow.

There is deliberately **no foreign key** from ``evidence.content_hash`` to
``evidence_blobs``. Retention prunes payloads long before it prunes the record
that they were collected: an evidence row whose blob has aged out still says
truthfully what was read, when, and with what result. A foreign key would force
those two lifetimes to be one.

``cloud_snapshots`` is untouched and remains what replay reads. Evidence rows
are written beside it, not instead of it, until the reconstruction they allow
has been proven against real scans.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    # --- the record ---------------------------------------------------------
    # Renaming carries the table's policies, indexes and constraints with it,
    # which is the point: the RLS this table already had is the RLS evidence
    # needs, and re-creating it would be a chance to get it subtly wrong.
    op.execute("ALTER TABLE scan_collection_results RENAME TO evidence;")
    op.execute("ALTER TABLE evidence RENAME COLUMN task_key TO evidence_key;")

    op.execute(
        """
        ALTER TABLE evidence
            ADD COLUMN provider varchar(16) NOT NULL DEFAULT 'azure',
            -- When the provider was read, not when the row was written. The two
            -- are the same for a live scan and months apart for a replay, and
            -- freshness is about the first.
            ADD COLUMN collected_at timestamptz NOT NULL DEFAULT now(),
            -- The permissions the read was made under, copied from the task's
            -- own declaration. This is what turns "we could not read storage"
            -- into "we could not read storage, and here is the action your role
            -- is missing" without anybody correlating two files by hand.
            ADD COLUMN permissions jsonb NOT NULL DEFAULT '[]'::jsonb,
            -- NULL where there is no payload to point at: a task that failed
            -- outright collected nothing, and a hash of nothing would claim
            -- otherwise.
            ADD COLUMN content_hash char(64),
            ADD COLUMN byte_size integer NOT NULL DEFAULT 0;
        """
    )
    # Rename what the old name is now wrong for. The unique constraint still
    # says the same thing -- one reading per listing per scope per scan.
    op.execute(
        """
        ALTER TABLE evidence
            RENAME CONSTRAINT uq_scan_collection_scan_account_task
            TO uq_evidence_scan_account_key;
        """
    )
    op.execute("ALTER INDEX ix_scan_collection_outcome RENAME TO ix_evidence_outcome;")
    op.execute(
        """
        ALTER INDEX uq_scan_collection_directory_task
            RENAME TO uq_evidence_directory_key;
        """
    )
    op.execute(
        """
        ALTER TABLE evidence
            RENAME CONSTRAINT ck_scan_collection_one_scope TO ck_evidence_one_scope;
        """
    )
    # Freshness is the question the planner will ask of this table: what do we
    # already hold for this scope, recently enough to reuse. Indexed now because
    # the column is new and the index is cheap on an empty-ish table.
    op.execute(
        """
        CREATE INDEX ix_evidence_freshness
            ON evidence (organization_id, cloud_account_id, evidence_key, collected_at DESC);
        """
    )

    # --- the payloads -------------------------------------------------------
    op.execute(
        """
        CREATE TABLE evidence_blobs (
            organization_id  uuid NOT NULL
                             REFERENCES organizations(id) ON DELETE CASCADE,
            content_hash     char(64) NOT NULL,
            payload          jsonb NOT NULL,
            byte_size        integer NOT NULL DEFAULT 0,
            first_stored_at  timestamptz NOT NULL DEFAULT now(),
            last_seen_at     timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (organization_id, content_hash)
        );
        """
    )
    # Retention reads this: the oldest payloads nothing has referenced lately.
    op.execute(
        """
        CREATE INDEX ix_evidence_blobs_last_seen
            ON evidence_blobs (organization_id, last_seen_at);
        """
    )

    # Row-level isolation on the same terms as every other tenant-owned table,
    # written the same way 0007 writes it. Four policies, not one: the WITH
    # CHECK on write is what makes PostgreSQL itself refuse a row carrying
    # someone else's organization_id.
    op.execute("ALTER TABLE evidence_blobs ENABLE ROW LEVEL SECURITY;")
    for action, clause in (
        ("SELECT", "USING (app.is_member(organization_id))"),
        ("INSERT", "WITH CHECK (app.is_member(organization_id))"),
        (
            "UPDATE",
            "USING (app.is_member(organization_id)) "
            "WITH CHECK (app.is_member(organization_id))",
        ),
        ("DELETE", "USING (app.is_member(organization_id))"),
    ):
        op.execute(
            f"CREATE POLICY evidence_blobs_tenant_{action.lower()} "
            f"ON evidence_blobs FOR {action} {clause};"
        )

    # As in 0007: 0001's ALTER DEFAULT PRIVILEGES covered the tables that
    # existed then, not this one.
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON evidence_blobs TO authenticated;"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS evidence_blobs;")
    op.execute("DROP INDEX IF EXISTS ix_evidence_freshness;")
    op.execute(
        """
        ALTER TABLE evidence
            DROP COLUMN provider,
            DROP COLUMN collected_at,
            DROP COLUMN permissions,
            DROP COLUMN content_hash,
            DROP COLUMN byte_size;
        """
    )
    op.execute(
        """
        ALTER TABLE evidence
            RENAME CONSTRAINT ck_evidence_one_scope TO ck_scan_collection_one_scope;
        """
    )
    op.execute(
        """
        ALTER INDEX uq_evidence_directory_key
            RENAME TO uq_scan_collection_directory_task;
        """
    )
    op.execute("ALTER INDEX ix_evidence_outcome RENAME TO ix_scan_collection_outcome;")
    op.execute(
        """
        ALTER TABLE evidence
            RENAME CONSTRAINT uq_evidence_scan_account_key
            TO uq_scan_collection_scan_account_task;
        """
    )
    op.execute("ALTER TABLE evidence RENAME COLUMN evidence_key TO task_key;")
    op.execute("ALTER TABLE evidence RENAME TO scan_collection_results;")
