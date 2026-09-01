"""Whether the fix actually took, asked as a question rather than noticed.

Revision ID: 0017
Revises: 0016

Marking a task done recorded a timestamp and told the customer to run a scan.
If they did, and if that scan happened to produce a PASS on the same rule and
asset, the finding resolved. Everything about that sentence is a coincidence:
nothing recorded what CloudGuard was expecting to see, nothing looked again on
its own, and every way of *not* being verified came out as the same silence --
the finding stayed open and the customer was told nothing.

A row here is the expectation, written when the claim is made. Scans settle it;
a scheduler retries it on a backoff, because a cloud takes time to agree with
itself and a check run a minute after a change reports the environment as it
was. Reporting that as "still failing" is how a verification feature teaches
customers to distrust its answers.

The outcomes are three, not two. STILL_FAILING is CloudGuard looking and
disagreeing. INSUFFICIENT_EVIDENCE is CloudGuard failing to look -- its own
problem to explain rather than the customer's to fix. That is the same
distinction the rule algebra draws between FAIL and UNKNOWN, carried up to the
one screen where the customer is being told whether their work counted.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE remediation_verifications (
            id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id  uuid NOT NULL
                             REFERENCES organizations(id) ON DELETE CASCADE,
            finding_id       uuid NOT NULL
                             REFERENCES findings(id) ON DELETE CASCADE,
            -- SET NULL: a task may be deleted while the question its completion
            -- raised is still open, and the question is the thing worth keeping.
            remediation_task_id uuid
                             REFERENCES remediation_tasks(id) ON DELETE SET NULL,

            -- What must be observed, spelled out rather than implied by the
            -- finding. A finding can be reclassified and a rule retired; this
            -- is a statement about a moment and has to survive both.
            rule_id          varchar(32) NOT NULL,
            resource_id      uuid REFERENCES cloud_resources(id) ON DELETE CASCADE,

            -- Which scope has to be read to answer it, so the scheduler can
            -- start the cheapest scan that could settle it.
            cloud_account_id uuid REFERENCES cloud_accounts(id) ON DELETE CASCADE,
            connection_id    uuid REFERENCES cloud_connections(id) ON DELETE CASCADE,

            status           varchar(24) NOT NULL DEFAULT 'PENDING',
            -- When the customer said it was fixed, not when this row was
            -- written. Every "how long did this take" is measured from here.
            claimed_at       timestamptz NOT NULL DEFAULT now(),
            claimed_by_user_id uuid,

            attempts         integer NOT NULL DEFAULT 0,
            last_attempt_at  timestamptz,
            next_attempt_at  timestamptz,
            last_state       varchar(16),
            -- Whether any attempt reached an explicit FAIL. Decides the
            -- terminal answer when attempts run out: having once seen the check
            -- fail is stronger and truer than "we could not tell".
            observed_failure boolean NOT NULL DEFAULT false,
            detail           text,

            verified_by_scan_id uuid REFERENCES scans(id) ON DELETE SET NULL,
            settled_at       timestamptz,

            created_at       timestamptz NOT NULL DEFAULT now(),
            updated_at       timestamptz NOT NULL DEFAULT now(),

            CONSTRAINT ck_remediation_verifications_status
                CHECK (status IN ('PENDING','VERIFIED','STILL_FAILING',
                                  'INSUFFICIENT_EVIDENCE','ABANDONED'))
        );
        """
    )
    # One live verification per finding. Marking the same task done twice is
    # restating one claim, not making a second, and two pending rows would spend
    # two sets of attempts answering one question.
    op.execute(
        """
        CREATE UNIQUE INDEX uq_remediation_verifications_open
            ON remediation_verifications (finding_id)
         WHERE status = 'PENDING';
        """
    )
    # What the scheduler reads on every tick: the few that are due, never the
    # history of everything ever claimed.
    op.execute(
        """
        CREATE INDEX ix_remediation_verifications_due
            ON remediation_verifications (next_attempt_at)
         WHERE status = 'PENDING';
        """
    )
    op.execute(
        """
        CREATE INDEX ix_remediation_verifications_org_status
            ON remediation_verifications (organization_id, status);
        """
    )

    op.execute("ALTER TABLE remediation_verifications ENABLE ROW LEVEL SECURITY;")
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
            f"CREATE POLICY remediation_verifications_tenant_{action.lower()} "
            f"ON remediation_verifications FOR {action} {clause};"
        )
    # The worker settles these, so unlike context declarations it writes here as
    # well as reads. The asymmetry is the same principle either way: a scan may
    # record what it observed, and may not invent what the customer claimed.
    for action, clause in (
        ("SELECT", "USING (app.current_org() = organization_id)"),
        (
            "UPDATE",
            "USING (app.current_org() = organization_id) "
            "WITH CHECK (app.current_org() = organization_id)",
        ),
    ):
        op.execute(
            f"CREATE POLICY remediation_verifications_worker_{action.lower()} "
            f"ON remediation_verifications FOR {action} TO cloudguard_worker {clause};"
        )

    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON remediation_verifications "
        "TO authenticated;"
    )
    op.execute(
        "GRANT SELECT, UPDATE ON remediation_verifications TO cloudguard_worker;"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS remediation_verifications;")
