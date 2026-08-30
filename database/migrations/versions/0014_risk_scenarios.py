"""A path becomes a risk, so the graph reaches the place customers look.

Revision ID: 0014
Revises: 0013

The asset graph can say that an internet-facing host runs as an identity
holding a role over the subscription the customer's data sits in. Until now it
said so on a page of its own, and nothing else knew: the findings list still
showed five unrelated rows, the risk list still ranked them separately, and the
security score still counted them as five ordinary problems.

``risks`` gains two columns and a key so the same table can hold both kinds.
That table was built for this -- ``risk_findings`` has always been a junction,
and the comment on it says grouping several findings into one risk later is a
change in the pipeline rather than a migration. This is that later, plus the
three columns needed to tell the two kinds apart and to remember the route.

**Scenario risks are deliberately excluded from the security score.** The
score joins risks to findings, so a risk with four members would deduct four
times -- and even deducting once would be charging a customer twice for one
problem they have already been charged for through its parts. A scenario
re-ranks and explains; it does not add a new fault to the tally. The dashboard
query gains that filter in the same commit.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE risks
            ADD COLUMN kind varchar(16) NOT NULL DEFAULT 'FINDING',
            -- The route, hop by hop, as the graph described it. Stored so the
            -- risk can explain itself without rebuilding the graph, and
            -- rewritten on every scan like every other derived column here --
            -- a route the customer has since closed is exactly as stale as a
            -- finding they have since fixed, and gets corrected the same way.
            ADD COLUMN path jsonb NOT NULL DEFAULT '[]'::jsonb,
            -- What makes a scenario the same scenario between scans. A risk
            -- from a finding is identified by the finding; a risk from a path
            -- has no finding of its own, so it is identified by where the path
            -- starts and ends.
            ADD COLUMN scenario_key varchar(2100);
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX uq_risks_scenario
            ON risks (organization_id, scenario_key)
         WHERE scenario_key IS NOT NULL;
        """
    )
    # What the risk list reads to separate the two kinds.
    op.execute("CREATE INDEX ix_risks_kind ON risks (organization_id, kind);")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_risks_kind;")
    op.execute("DROP INDEX IF EXISTS uq_risks_scenario;")
    # The scenario rows go with the columns that made them scenarios. Left
    # behind they would be ordinary risks with a title about an attack path and
    # no route to show.
    op.execute("DELETE FROM risks WHERE kind = 'ATTACK_PATH';")
    op.execute(
        """
        ALTER TABLE risks
            DROP COLUMN scenario_key,
            DROP COLUMN path,
            DROP COLUMN kind;
        """
    )
