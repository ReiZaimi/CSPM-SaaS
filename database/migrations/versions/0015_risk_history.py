"""What the posture was, each time CloudGuard looked.

Revision ID: 0015
Revises: 0014

"Did my risk go up?" is the question a customer asks after doing the work, and
nothing recorded the answer. The dashboard showed a delta, and that delta was an
estimate rather than a measurement: it reconstructed a prior score by adding
back the deduction for every finding ever verified as fixed, so it answered
"how much better than before we started" and called it "movement since the last
scan". Those diverge immediately and never reconverge.

It also broke the moment a finding could belong to two risks. The estimate
counted deductions through ``risk_findings``, and a finding that is both its own
risk and a member of a scenario is joined twice -- so every verified fix on a
route recovered double.

One row per scan, denormalized on purpose. This is a time series, and the whole
point of it is being read as a run of numbers without joining anything: the
counts here are what was true at that moment, not a query that would answer
differently tomorrow because a finding has since been reclassified.

Written only by a scan that actually observed something. A replay of a
superseded capture reports what today's rules would have found and changes
nothing, so it records nothing here either -- a history with entries nobody
observed would make the line move on days when nothing was looked at.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE risk_history (
            id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id    uuid NOT NULL
                               REFERENCES organizations(id) ON DELETE CASCADE,
            -- The scan that observed it. SET NULL rather than CASCADE: pruning
            -- an execution log must not rewrite history, exactly as deleting a
            -- scan leaves the findings it raised alone.
            scan_id            uuid REFERENCES scans(id) ON DELETE SET NULL,

            -- When the provider was read, not when the row was written. A
            -- replay carries its capture's own time, and a history plotted on
            -- write time would put month-old evidence at today's date.
            observed_at        timestamptz NOT NULL,

            security_score     integer NOT NULL,
            open_finding_count integer NOT NULL DEFAULT 0,
            -- Counts as they stood, not a query to be re-run. A finding
            -- reclassified next month must not silently rewrite what last
            -- month's posture was.
            findings_by_severity jsonb NOT NULL DEFAULT '{}'::jsonb,
            risk_bands           jsonb NOT NULL DEFAULT '{}'::jsonb,
            -- Routes open at that moment. "Did a new attack path appear" is
            -- answerable from the risks table itself; this is what makes "are
            -- there more of them than last week" answerable at a glance.
            attack_path_count  integer NOT NULL DEFAULT 0,

            created_at         timestamptz NOT NULL DEFAULT now()
        );
        """
    )
    # One reading per scan. A scan whose ANALYZE step is retried must correct
    # its entry rather than add a second one, or a retry would show as a real
    # movement in posture.
    op.execute(
        """
        CREATE UNIQUE INDEX uq_risk_history_scan
            ON risk_history (scan_id)
         WHERE scan_id IS NOT NULL;
        """
    )
    # How the series is read: newest first, per tenant.
    op.execute(
        """
        CREATE INDEX ix_risk_history_timeline
            ON risk_history (organization_id, observed_at DESC);
        """
    )

    op.execute("ALTER TABLE risk_history ENABLE ROW LEVEL SECURITY;")
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
            f"CREATE POLICY risk_history_tenant_{action.lower()} "
            f"ON risk_history FOR {action} {clause};"
        )
    # And the worker's arm, which is how a scan writes its own entry.
    for action, clause in (
        ("SELECT", "USING (app.current_org() = organization_id)"),
        ("INSERT", "WITH CHECK (app.current_org() = organization_id)"),
        (
            "UPDATE",
            "USING (app.current_org() = organization_id) "
            "WITH CHECK (app.current_org() = organization_id)",
        ),
        ("DELETE", "USING (app.current_org() = organization_id)"),
    ):
        op.execute(
            f"CREATE POLICY risk_history_worker_{action.lower()} "
            f"ON risk_history FOR {action} TO cloudguard_worker {clause};"
        )

    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON risk_history TO authenticated;")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON risk_history TO cloudguard_worker;"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS risk_history;")
