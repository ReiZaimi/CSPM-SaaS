"""What a reading was a reading of, and under which contract.

``permissions`` already said what the read needed. This says what it called and
which ``api-version`` it called under, and the second half is the one that
carries weight: Azure's response shape is a function of the api-version, so a
field absent from a stored capture is ambiguous between "the customer never set
it" and "we asked a contract that does not return it". A rule reading the second
as the first raises a finding out of CloudGuard's own staleness -- the same
overclaim as a PASS nobody earned, arrived at from the other side.

Additive with a default, no backfill, following 0022 and 0023. Readings taken
before this carry ``[]``, which reads as "not recorded" rather than as "called
nothing" -- and the API keeps those apart.

Revision ID: 0024
Revises: 0023
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE evidence
            ADD COLUMN endpoints jsonb NOT NULL DEFAULT '[]'::jsonb;
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE evidence DROP COLUMN endpoints;")
