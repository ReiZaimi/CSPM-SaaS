"""A reading is scoped by region as well as by account.

Azure's ARM lists a subscription's resources globally, so one scan of one
subscription produced one reading per evidence key and the unique constraint
over ``(scan_id, cloud_account_id, evidence_key)`` held. AWS does not work that
way: almost every ``Describe*`` is per region, so an account with seventeen
enabled regions produces seventeen readings of ``security_groups`` -- seventeen
rows under one key, which that constraint refuses.

The region goes beside the key rather than into it. A rule depends on evidence
and never on a region, so ``evidence_key`` has to keep meaning what
``requires_evidence`` names; the seventeen rows are one answer to "did we see
the security groups", and the coverage report is where they are aggregated back
into one.

NULL means the listing is not regional -- every row written before this
migration, and on AWS the IAM, S3 and Organizations reads. The constraint is
rebuilt with NULLS NOT DISTINCT, because both of its nullable columns mean "not
scoped that way" and two readings that are both unscoped are the same reading.
Under Postgres's default they would be distinct from each other and the
constraint would stop protecting the rows it exists for.

That change can in principle reject rows the old constraint allowed -- two
directory readings of one key in one scan, which the scanner does not write and
never has -- so the duplicates are removed first rather than the migration
failing on a customer's database.

Revision ID: 0033
Revises: 0032
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0033"
down_revision: str | None = "0032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE evidence ADD COLUMN region varchar(32);")

    # Keep the newest of any duplicate group. Expected to match nothing: the
    # only rows the old constraint could not already separate are directory
    # readings, and a scan takes one directory capture.
    op.execute(
        """
        DELETE FROM evidence e
        USING evidence newer
        WHERE e.scan_id = newer.scan_id
          AND e.evidence_key = newer.evidence_key
          AND e.cloud_account_id IS NOT DISTINCT FROM newer.cloud_account_id
          AND (e.created_at, e.id) < (newer.created_at, newer.id);
        """
    )

    op.execute(
        "ALTER TABLE evidence DROP CONSTRAINT IF EXISTS uq_evidence_scan_account_key;"
    )
    op.execute(
        "ALTER TABLE evidence ADD CONSTRAINT uq_evidence_scan_account_key "
        "UNIQUE NULLS NOT DISTINCT (scan_id, cloud_account_id, evidence_key, region);"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE evidence DROP CONSTRAINT IF EXISTS uq_evidence_scan_account_key;"
    )
    op.execute("ALTER TABLE evidence DROP COLUMN region;")
    op.execute(
        "ALTER TABLE evidence ADD CONSTRAINT uq_evidence_scan_account_key "
        "UNIQUE (scan_id, cloud_account_id, evidence_key);"
    )
