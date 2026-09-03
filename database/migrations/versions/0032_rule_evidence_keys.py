"""Which readings each rule depends on, mirrored beside its framework mappings.

The compliance view joins the ``rules`` table rather than importing the Python
registry, for a reason the table's own docstring gives: a rule deleted from the
registry keeps its row, so the controls it used to answer for do not silently
become uncovered. That worked for the mappings and left the chain one link
short -- a control's verdict rests on its rules, and a rule's verdict rests on
the evidence it declares, so following a framework's control back to the
provider call behind it stopped at the rule id.

``requires_evidence`` is that link, mirrored from ``SecurityRule
.requires_evidence`` by the same startup sync that writes the mappings.

Defaulted to an empty array rather than backfilled: the sync runs on every boot
and rewrites every row, so the first deploy fills it. An empty array reads as
"this rule declares no readings", which is true of a rule the sync has not
reached yet and true of the handful that genuinely read nothing.

Revision ID: 0032
Revises: 0031
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0032"
down_revision: str | None = "0031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE rules ADD COLUMN requires_evidence jsonb NOT NULL DEFAULT '[]'::jsonb;"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE rules DROP COLUMN requires_evidence;")
