"""What changed, rather than only what is true now.

Revision ID: 0018
Revises: 0017

The environment was described by its current state and two timestamps. "What
changed since last week" was answerable by diffing multi-megabyte snapshot blobs
in application code, which is another way of saying it was not answerable -- and
it is the question a customer asks first after a week of somebody else's
deployments.

A finding was worse. ``first_detected_at`` and ``resolved_at`` are two points on
a line nobody could see the rest of: one raised, fixed, regressed and fixed
again looked exactly like one raised and fixed once. On a product whose
north-star metric is *verified risk reduction*, that made the metric an estimate
over the current state rather than a measurement of what actually happened.

Two append-only tables, one row per change rather than one per scan, so a scan
that finds nothing different writes nothing and the feed records movement
instead of the fact of having looked. ``risk_history`` (migration 0015) is the
third leg of the same model and was built first, because a score that only
moves is easier to notice missing than a history that never existed.

``cloud_resources.absent_since`` comes with them, and it is what makes
disappearance a *transition* rather than a standing condition. Derived from
``last_seen_at`` instead, an absence would need a scan cadence nobody records,
and would re-report itself on every scan for ever.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

TENANT_POLICIES = (
    ("SELECT", "USING (app.is_member(organization_id))"),
    ("INSERT", "WITH CHECK (app.is_member(organization_id))"),
    (
        "UPDATE",
        "USING (app.is_member(organization_id)) "
        "WITH CHECK (app.is_member(organization_id))",
    ),
    ("DELETE", "USING (app.is_member(organization_id))"),
)

WORKER_POLICIES = (
    ("SELECT", "USING (app.current_org() = organization_id)"),
    ("INSERT", "WITH CHECK (app.current_org() = organization_id)"),
    (
        "UPDATE",
        "USING (app.current_org() = organization_id) "
        "WITH CHECK (app.current_org() = organization_id)",
    ),
    ("DELETE", "USING (app.current_org() = organization_id)"),
)


def _secure(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
    for action, clause in TENANT_POLICIES:
        op.execute(
            f"CREATE POLICY {table}_tenant_{action.lower()} "
            f"ON {table} FOR {action} {clause};"
        )
    for action, clause in WORKER_POLICIES:
        op.execute(
            f"CREATE POLICY {table}_worker_{action.lower()} "
            f"ON {table} FOR {action} TO cloudguard_worker {clause};"
        )
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO authenticated;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO cloudguard_worker;")


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE cloud_resources
            ADD COLUMN absent_since timestamptz;
        """
    )

    op.execute(
        """
        CREATE TABLE asset_change_events (
            id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL
                            REFERENCES organizations(id) ON DELETE CASCADE,
            resource_id     uuid NOT NULL
                            REFERENCES cloud_resources(id) ON DELETE CASCADE,
            -- SET NULL: pruning an execution log must not rewrite what happened
            -- to the environment.
            scan_id         uuid REFERENCES scans(id) ON DELETE SET NULL,

            change          varchar(24) NOT NULL,
            -- NULL on APPEARED and DISAPPEARED, which are about the asset
            -- rather than about one of its attributes.
            previous_value  varchar(32),
            current_value   varchar(32),

            -- When the provider was read, not when the row was written.
            observed_at     timestamptz NOT NULL,
            created_at      timestamptz NOT NULL DEFAULT now(),

            CONSTRAINT ck_asset_change_events_change
                CHECK (change IN ('APPEARED','DISAPPEARED','EXPOSURE_CHANGED',
                                  'SENSITIVITY_CHANGED','CRITICALITY_CHANGED'))
        );
        """
    )
    op.execute(
        """
        CREATE INDEX ix_asset_change_events_feed
            ON asset_change_events (organization_id, observed_at DESC);
        """
    )
    op.execute(
        """
        CREATE INDEX ix_asset_change_events_resource
            ON asset_change_events (resource_id, observed_at DESC);
        """
    )
    _secure("asset_change_events")

    op.execute(
        """
        CREATE TABLE finding_events (
            id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL
                            REFERENCES organizations(id) ON DELETE CASCADE,
            finding_id      uuid NOT NULL
                            REFERENCES findings(id) ON DELETE CASCADE,
            scan_id         uuid REFERENCES scans(id) ON DELETE SET NULL,
            -- Not an FK: auth.users belongs to Supabase.
            user_id         uuid,

            event           varchar(24) NOT NULL,
            previous_status varchar(24),
            current_status  varchar(24) NOT NULL,
            detail          text,

            observed_at     timestamptz NOT NULL,
            created_at      timestamptz NOT NULL DEFAULT now(),

            CONSTRAINT ck_finding_events_event
                CHECK (event IN ('DETECTED','REOPENED','RESOLVED',
                                 'RISK_ACCEPTED','STATUS_CHANGED'))
        );
        """
    )
    op.execute(
        """
        CREATE INDEX ix_finding_events_timeline
            ON finding_events (finding_id, observed_at DESC);
        """
    )
    op.execute(
        """
        CREATE INDEX ix_finding_events_org
            ON finding_events (organization_id, observed_at DESC);
        """
    )
    _secure("finding_events")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS finding_events;")
    op.execute("DROP TABLE IF EXISTS asset_change_events;")
    op.execute("ALTER TABLE cloud_resources DROP COLUMN IF EXISTS absent_since;")
