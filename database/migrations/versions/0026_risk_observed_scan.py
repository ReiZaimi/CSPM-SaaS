"""Which reading of the estate a route was seen in.

A finding says which scan detected it. A *scenario* -- a route through the graph
-- said nothing, and it is the risk kind where the question matters most: a path
is a claim about how an environment is wired, assembled from one scan's
normalized state, and "this route exists" is only ever true as of a reading.

Without it the attack-path screens can say a route is open and cannot say when
anybody last looked. A customer who fixed the middle hop this morning has no way
to tell a route that survived the latest scan from one nothing has re-checked
since Tuesday, and the two look identical.

``ON DELETE SET NULL`` rather than CASCADE: risks outlive scans, exactly as
findings do, and a pruned scan must not take the route it observed with it. The
row then says it was seen, and no longer which reading saw it -- which is worse
than the full answer and much better than the route silently vanishing.

Additive and nullable, no backfill, following 0022-0025. Existing routes read as
"not recorded" until the next scan observes them again, which for a live
connection is the next scheduled run.

Revision ID: 0026
Revises: 0025
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0026"
down_revision: str | None = "0025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE risks
            ADD COLUMN observed_scan_id uuid
                REFERENCES scans(id) ON DELETE SET NULL;
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE risks DROP COLUMN observed_scan_id;")
