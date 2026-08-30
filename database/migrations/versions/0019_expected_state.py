"""What CloudGuard will look for, written down when the claim is made.

Revision ID: 0019
Revises: 0018

A verification already recorded that a customer claims a fix and waited for the
rule to pass. That is the right test and a poor explanation: the customer was
told CloudGuard would check, never what it would check for.

The expected state now travels with the claim -- the settings, in the provider's
own vocabulary, that have to be true for the finding to close. Copied onto the
row rather than read from the rule at display time, for the reason the
remediation prose is copied onto a finding: a rule's declaration can change, and
a customer looking at a two-week-old claim should see what was expected of them
when they made it, not what would be expected of them today.

Empty for a rule that has no declaration yet, which stays distinguishable from a
rule for which no machine-readable expectation is possible.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE remediation_verifications
            ADD COLUMN expected_state jsonb NOT NULL DEFAULT '[]'::jsonb;
        """
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE remediation_verifications DROP COLUMN IF EXISTS expected_state;"
    )
