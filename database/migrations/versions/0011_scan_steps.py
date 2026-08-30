"""A scan becomes durable steps rather than one task that must survive it all.

Revision ID: 0011
Revises: 0010

A scan ran as a single Celery task with no retries: resolve the scope, read
every subscription in sequence, then interpret the lot. Three consequences, all
of them the same consequence.

**It could not be resumed.** A worker redeployed after reading nine
subscriptions out of ten had read nothing, because nothing durable recorded
that the nine were done. Migration 0009 gave that failure a way out -- the scan
is reclaimed and closed -- but closing it is not finishing it, and the customer
still runs the whole thing again.

**It could not be spread.** Fifty subscriptions were fifty sequential
collections inside one task, against a thirty-minute limit that is a safety net
for a small tenant and a ceiling on customer size for a large one.

**And one failure was the whole scan's failure.** Retrying meant retrying
everything, including the forty-nine subscriptions that were fine.

``scan_steps`` makes each stage a row: claimed under a lease, retried on its
own, and settled independently. The claim is the concurrency control -- an
``UPDATE ... WHERE status = 'PENDING' RETURNING id`` that exactly one worker
wins -- so two workers advancing the same scan cannot both run a step.

Deliberately not a general dependency graph. There is no ``depends_on`` array
and no edge table: a scan's shape is fixed in code and has been the same three
stages since the pipeline existed, so edges would be a mechanism with one
configuration and cycle detection for a graph nobody can author. Ordering by
kind expresses it in a query, and adding a stage later is a kind plus a line in
the readiness clause.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE scan_steps (
            id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id  uuid NOT NULL
                             REFERENCES organizations(id) ON DELETE CASCADE,
            scan_id          uuid NOT NULL
                             REFERENCES scans(id) ON DELETE CASCADE,

            kind             varchar(16) NOT NULL,
            -- Which subscription a COLLECT step reads. NULL on the step that
            -- reads the tenant directory, and on PLAN and ANALYZE, which are
            -- about the scan rather than about any one scope.
            cloud_account_id uuid REFERENCES cloud_accounts(id) ON DELETE CASCADE,

            status           varchar(16) NOT NULL DEFAULT 'PENDING',
            attempt          integer NOT NULL DEFAULT 0,
            max_attempts     integer NOT NULL DEFAULT 3,
            -- Held by whichever worker claimed it, extended while it reports
            -- progress. A worker that dies stops extending, and the reaper
            -- returns the step to PENDING rather than the scan to FAILED.
            lease_until      timestamptz,
            worker_id        varchar(128),
            error            text,

            started_at       timestamptz,
            finished_at      timestamptz,
            created_at       timestamptz NOT NULL DEFAULT now()
        );
        """
    )
    # One step per (scan, kind, scope). This is what makes PLAN idempotent: a
    # retried PLAN re-creates the same COLLECT steps and the insert conflicts
    # rather than doubling the collection.
    #
    # Two indexes because NULLs are distinct in a unique constraint, and the
    # steps with no account -- PLAN, ANALYZE, and the directory COLLECT -- are
    # exactly the ones that must not be duplicated either.
    op.execute(
        """
        CREATE UNIQUE INDEX uq_scan_steps_scoped
            ON scan_steps (scan_id, kind, cloud_account_id)
         WHERE cloud_account_id IS NOT NULL;
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX uq_scan_steps_unscoped
            ON scan_steps (scan_id, kind)
         WHERE cloud_account_id IS NULL;
        """
    )
    # What the dispatcher reads on every advance: this scan's steps and where
    # they have got to.
    op.execute(
        "CREATE INDEX ix_scan_steps_scan_status ON scan_steps (scan_id, status);"
    )
    # And what the reaper reads: claimed steps nobody is working on any more.
    op.execute(
        """
        CREATE INDEX ix_scan_steps_expired
            ON scan_steps (lease_until)
         WHERE status = 'RUNNING';
        """
    )

    op.execute("ALTER TABLE scan_steps ENABLE ROW LEVEL SECURITY;")
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
            f"CREATE POLICY scan_steps_tenant_{action.lower()} "
            f"ON scan_steps FOR {action} {clause};"
        )

    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON scan_steps TO authenticated;")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS scan_steps;")
