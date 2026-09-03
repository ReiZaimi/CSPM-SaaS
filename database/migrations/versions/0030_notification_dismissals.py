"""Letting a reader put one notification down.

Per reader, not per organization. Notifications belong to the estate -- what
happened, happened -- and whether somebody wants to keep seeing an item is a
fact about them, so a dismissal that deleted the row would let one person remove
another's news. Same asymmetry the read watermark already has, for the same
reason.

A row rather than a flag on ``notifications`` for the same reason again: the
table is shared, and there is nowhere on a shared row to record a decision one
person made.

Revision ID: 0030
Revises: 0029
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0030"
down_revision: str | None = "0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "notification_dismissals"


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE notification_dismissals (
          organization_id uuid NOT NULL
                            REFERENCES organizations(id) ON DELETE CASCADE,
          user_id         uuid NOT NULL,
          -- Cascades with the notification: a dismissal of something that no
          -- longer exists is a row nothing can ever read.
          notification_id uuid NOT NULL
                            REFERENCES notifications(id) ON DELETE CASCADE,
          dismissed_at    timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (organization_id, user_id, notification_id)
        );

        -- How the bell reads it: everything this person has put down, in one
        -- organization, as the subquery behind the listing.
        CREATE INDEX ix_notification_dismissals_reader
            ON notification_dismissals (organization_id, user_id);
        """
    )

    op.execute(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY;")
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
            f"CREATE POLICY {TABLE}_tenant_{action.lower()} "
            f"ON {TABLE} FOR {action} {clause};"
        )
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
            f"CREATE POLICY {TABLE}_worker_{action.lower()} "
            f"ON {TABLE} FOR {action} TO cloudguard_worker {clause};"
        )

    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {TABLE} TO authenticated;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {TABLE} TO cloudguard_worker;")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS notification_dismissals;")
