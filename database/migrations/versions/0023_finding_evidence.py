"""Which readings a finding rests on.

A finding has always carried an excerpt of its evidence. This carries the
citation: which listing, taken when, under which permissions, and the hash of
the bytes. The two are different claims -- an excerpt says what a rule saw, a
citation says where it came from and can be followed back to the payload.

Additive, with no backfill, following 0022: history is not rewritten by a
migration. Findings raised before this exist with no rows, and acquire them on
their next scan. The API distinguishes the two -- ``null`` for a finding that
predates provenance, ``[]`` for one whose rule cites nothing -- because an empty
list that meant either would be the ambiguity this table exists to remove.

Revision ID: 0023
Revises: 0022
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE finding_evidence (
          finding_id      uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
          evidence_key    varchar(64) NOT NULL,
          organization_id uuid NOT NULL
                            REFERENCES organizations(id) ON DELETE CASCADE,
          -- The reading, while it exists. SET NULL rather than CASCADE: findings
          -- outlive scans, and a pruned scan must not take the citation with it.
          evidence_id     uuid REFERENCES evidence(id) ON DELETE SET NULL,
          -- The citation, copied so it survives the row above. NULL hash where
          -- the reading produced nothing, which a failed collection did.
          content_hash    varchar(64),
          collected_at    timestamptz NOT NULL,
          -- No foreign key, deliberately: this is what remains after the scan
          -- that collected the reading has been deleted.
          source_scan_id  uuid,
          PRIMARY KEY (finding_id, evidence_key)
        );

        CREATE INDEX ix_finding_evidence_organization_id
            ON finding_evidence (organization_id);
        -- Reached from a payload: "which findings rest on these bytes", which is
        -- the question a re-evaluation of a stored capture asks.
        CREATE INDEX ix_finding_evidence_content_hash
            ON finding_evidence (content_hash);
        """
    )

    op.execute("ALTER TABLE finding_evidence ENABLE ROW LEVEL SECURITY;")
    # The member arm: every API request, through `cloudguard_app`.
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
            f"CREATE POLICY finding_evidence_tenant_{action.lower()} "
            f"ON finding_evidence FOR {action} {clause};"
        )
    # And the worker's arm, which is how a scan writes these at all: a
    # background scan has no signed-in user to resolve a membership through.
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
            f"CREATE POLICY finding_evidence_worker_{action.lower()} "
            f"ON finding_evidence FOR {action} TO cloudguard_worker {clause};"
        )

    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON finding_evidence TO authenticated;"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON finding_evidence TO cloudguard_worker;"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS finding_evidence;")
