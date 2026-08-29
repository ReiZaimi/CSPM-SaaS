"""Collection status as facts rather than prose.

Revision ID: 0007
Revises: 0006

What a scan managed to read was recorded only in ``scans.collection_errors``:
a map of category to a sentence, assembled for a human to read and answerable
by nothing else. It could not say whether a category had *failed* or merely
come back *truncated* -- a distinction that decides whether the customer has an
outage or a very large tenant -- nor which subscription it happened in, which
is the first question a tenant-wide scan raises.

One row per (scan, subscription, task), mirroring ``scan_rule_results``. That
table records what the rules concluded; this records whether they were entitled
to conclude anything.

``collection_errors`` stays. It is what drives rule degradation and what the
scan banner reads, and deriving it from these rows at read time would put a
join in front of every scan list for a string that is already correct.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE scan_collection_results (
            id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id  uuid NOT NULL
                             REFERENCES organizations(id) ON DELETE CASCADE,
            scan_id          uuid NOT NULL
                             REFERENCES scans(id) ON DELETE CASCADE,
            cloud_account_id uuid NOT NULL
                             REFERENCES cloud_accounts(id) ON DELETE CASCADE,
            task_key         varchar(64) NOT NULL,
            category         varchar(32) NOT NULL,
            outcome          varchar(16) NOT NULL,
            detail           text,
            item_count       integer NOT NULL DEFAULT 0,
            created_at       timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT uq_scan_collection_scan_account_task
                UNIQUE (scan_id, cloud_account_id, task_key)
        );
        """
    )
    op.execute(
        "CREATE INDEX ix_scan_collection_results_category "
        "ON scan_collection_results (category);"
    )
    op.execute(
        "CREATE INDEX ix_scan_collection_outcome "
        "ON scan_collection_results (organization_id, outcome);"
    )

    # Row-level isolation on the same terms as every other tenant-owned table.
    # Four policies, not one: the WITH CHECK on write is what makes PostgreSQL
    # itself refuse a row carrying someone else's organization_id, so a bug in
    # the service layer cannot produce cross-tenant data (0001, TENANT_TABLES).
    op.execute("ALTER TABLE scan_collection_results ENABLE ROW LEVEL SECURITY;")
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
            f"CREATE POLICY scan_collection_results_tenant_{action.lower()} "
            f"ON scan_collection_results FOR {action} {clause};"
        )

    # 0001 granted table privileges with ALL TABLES IN SCHEMA public, which
    # applies to the tables that existed then and not to this one.
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON scan_collection_results "
        "TO authenticated;"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS scan_collection_results;")
