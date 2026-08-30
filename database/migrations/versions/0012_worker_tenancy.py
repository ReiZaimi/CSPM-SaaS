"""PostgreSQL constrains the worker to one organization, instead of us doing it.

Revision ID: 0012
Revises: 0011

The API is tenant-isolated twice over: the service layer derives
``organization_id`` from a verified JWT, and row-level security re-checks the
same thing because the request connects as ``cloudguard_app``, which owns
nothing. The worker has only the first half. It connects as the table owner --
RLS does not apply to it -- so every ``organization_id`` filter in the scan
pipeline is hand-written, and the isolation guarantee is "somebody read the
pipeline carefully". That is true today and it is not a mechanism.

``cloudguard_worker`` is the mechanism. A second policy arm on every
tenant-owned table trusts a session setting rather than a membership lookup,
because a background scan has no user to resolve membership for:

    USING (app.current_org() = organization_id)

and the worker sets ``app.organization_id`` for the length of one scan's
transaction. PostgreSQL then refuses a read or a write outside that
organization however the query was written.

**The arm is granted to that role only.** Adding it to the policies the request
path uses would hand ``authenticated`` a bypass it never needs -- anything able
to run arbitrary SQL as that role could set the claim and read another tenant,
which is the guarantee this migration exists to strengthen, weakened.

Two things are deliberately left alone.

*Housekeeping stays on the owner connection.* The reaper looks for abandoned
work across every organization, which is exactly what a per-organization
session cannot see. It is a small, enumerable set of queries that scope
nothing on purpose, and pretending otherwise would mean inventing a
"see everything" claim -- a bypass with a friendly name.

*The role is created without login.* Policies need it to exist; only the
operator should decide its password, in ``infrastructure/supabase/roles.sql``
alongside the one for ``cloudguard_app``. Until they do, the worker falls back
to the owner connection and logs that it is doing so, so this migration changes
no behaviour on its own.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

# Every table carrying organization_id with RLS enabled: 0001's original set,
# plus the ones added since. Listed rather than derived because a migration
# describes the database at the moment it ran.
TENANT_TABLES = [
    "cloud_accounts",
    "cloud_connections",
    "cloud_resources",
    "resource_relationships",
    "scans",
    "scan_steps",
    "cloud_snapshots",
    "scan_rule_results",
    "scan_evaluation_gaps",
    "evidence",
    "evidence_blobs",
    "findings",
    "risks",
    "risk_findings",
    "remediation_tasks",
    "exceptions",
    "audit_logs",
]


def upgrade() -> None:
    # NOLOGIN: the policies below need the role to exist, and nothing else
    # about it should be decided here. The operator grants it a password and
    # LOGIN in roles.sql, which is also where they chose the one for
    # cloudguard_app.
    op.execute(
        """
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cloudguard_worker') THEN
            CREATE ROLE cloudguard_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
          END IF;
        END $$;
        """
    )

    # The organization this session is acting for, or NULL when nothing set it.
    #
    # ``true`` for missing_ok is load-bearing: an unset setting must read as
    # NULL rather than raise, and ``NULL = organization_id`` is NULL rather
    # than true -- so a worker session that forgot to declare its organization
    # sees no rows at all. Failing closed is the only acceptable direction for
    # this particular mistake.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.current_org() RETURNS uuid
        LANGUAGE sql STABLE AS $$
          SELECT NULLIF(current_setting('app.organization_id', true), '')::uuid
        $$;
        """
    )

    op.execute("GRANT USAGE ON SCHEMA app TO cloudguard_worker;")
    op.execute("GRANT EXECUTE ON FUNCTION app.current_org() TO cloudguard_worker;")

    for table in TENANT_TABLES:
        op.execute(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO cloudguard_worker;"
        )
        op.execute(
            f"CREATE POLICY {table}_worker_select ON {table} FOR SELECT "
            "TO cloudguard_worker USING (app.current_org() = organization_id);"
        )
        op.execute(
            f"CREATE POLICY {table}_worker_insert ON {table} FOR INSERT "
            "TO cloudguard_worker WITH CHECK (app.current_org() = organization_id);"
        )
        op.execute(
            f"CREATE POLICY {table}_worker_update ON {table} FOR UPDATE "
            "TO cloudguard_worker USING (app.current_org() = organization_id) "
            "WITH CHECK (app.current_org() = organization_id);"
        )
        op.execute(
            f"CREATE POLICY {table}_worker_delete ON {table} FOR DELETE "
            "TO cloudguard_worker USING (app.current_org() = organization_id);"
        )

    # The rule catalogue is global rather than tenant-owned, and the worker
    # reads it on every scan. 0001 made it readable by everyone; that policy
    # names no role, so it already covers this one -- the grant is what was
    # missing.
    op.execute("GRANT SELECT ON rules TO cloudguard_worker;")
    # Membership is read to resolve who triggered a scan. Read-only, and never
    # through app.is_member: the worker has no user.
    op.execute("GRANT SELECT ON organizations, organization_members TO cloudguard_worker;")


def downgrade() -> None:
    for table in TENANT_TABLES:
        for action in ("select", "insert", "update", "delete"):
            op.execute(f"DROP POLICY IF EXISTS {table}_worker_{action} ON {table};")
        op.execute(f"REVOKE ALL ON {table} FROM cloudguard_worker;")

    op.execute("REVOKE ALL ON rules FROM cloudguard_worker;")
    op.execute("REVOKE ALL ON organizations, organization_members FROM cloudguard_worker;")
    op.execute("REVOKE ALL ON SCHEMA app FROM cloudguard_worker;")
    op.execute("DROP FUNCTION IF EXISTS app.current_org();")
    # The role itself is left in place. Dropping it would fail wherever a
    # connection string still names it, and an unused NOLOGIN role costs
    # nothing.
