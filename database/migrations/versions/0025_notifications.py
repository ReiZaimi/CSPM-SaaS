"""What happened that a person has not seen yet.

Two tables and a deliberate asymmetry. Notifications belong to an organization,
because what happened happened to the estate rather than to a reader. Read state
belongs to a person, as a watermark rather than a flag per row: the question is
"what since I last looked", which has one answer and one timestamp -- and
per-row read state would make the badge a number about somebody's habits instead
of about their environment.

The unique index is the load-bearing part. Deriving is idempotent by
construction rather than by care: two workers running the sweep at once, or one
running twice after a retry, insert the same key and the second is refused. A
duplicate notification is the failure a reader actually notices.

Revision ID: 0025
Revises: 0024
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0025"
down_revision: str | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("notifications", "notification_reads")


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE notifications (
          id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id uuid NOT NULL
                            REFERENCES organizations(id) ON DELETE CASCADE,
          kind            varchar(32) NOT NULL,
          title           varchar(400) NOT NULL,
          detail          text,
          -- A path, not a URL. The client owns its routing, and a stored
          -- absolute link rots the day a route is renamed.
          link            varchar(500),
          subject_id      varchar(200) NOT NULL,
          -- When the thing happened, which is not when this row was written:
          -- the sweep runs on a timer, and every question a reader has is about
          -- the first.
          event_at        timestamptz NOT NULL,
          created_at      timestamptz NOT NULL DEFAULT now()
        );

        CREATE INDEX ix_notifications_organization_id
            ON notifications (organization_id);
        -- How the bell reads: newest first, within one organization.
        CREATE INDEX ix_notifications_org_event_at
            ON notifications (organization_id, event_at DESC);
        -- Idempotence, enforced rather than intended.
        CREATE UNIQUE INDEX uq_notifications_subject
            ON notifications (organization_id, kind, subject_id, event_at);

        CREATE TABLE notification_reads (
          organization_id uuid NOT NULL
                            REFERENCES organizations(id) ON DELETE CASCADE,
          user_id         uuid NOT NULL,
          read_through    timestamptz NOT NULL,
          PRIMARY KEY (organization_id, user_id)
        );
        """
    )

    for table in TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
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
                f"CREATE POLICY {table}_tenant_{action.lower()} "
                f"ON {table} FOR {action} {clause};"
            )
        # And the worker's arm, which is how the sweep writes these at all: a
        # background job has no signed-in user to resolve a membership through.
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
                f"CREATE POLICY {table}_worker_{action.lower()} "
                f"ON {table} FOR {action} TO cloudguard_worker {clause};"
            )

        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO authenticated;")
        op.execute(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO cloudguard_worker;"
        )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS notification_reads;")
    op.execute("DROP TABLE IF EXISTS notifications;")
