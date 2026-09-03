"""Which scan actually read the provider, where that is not this one.

Evidence inside its reuse window is carried into the next scan rather than
re-read. That scan writes a row of its own, under its own ``scan_id``, holding
the original ``collected_at`` -- so the age of the reading survived and the
authorship of it did not. Everything downstream reads ``scan_id`` as "the scan
that collected this", because until a reading could be carried that is exactly
what it meant.

``finding_evidence.source_scan_id`` is where it surfaces. Its own comment says
the collecting scan is not necessarily the scan that raised the finding, and it
is copied from ``evidence.scan_id`` -- which names the scan that reused the
reading. A customer following a citation back to "which reading is this finding
resting on" was handed a scan that made no such call.

Additive and nullable, no backfill. NULL keeps its natural meaning: this row is
the reading. Existing carried rows stay as they are and cannot be corrected --
the fact was never recorded -- and they read as self-collected, which is what
they already claimed.

Revision ID: 0031
Revises: 0030
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0031"
down_revision: str | None = "0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # No foreign key, deliberately, matching ``finding_evidence.source_scan_id``:
    # provenance outlives the scan it points at, and a reference that cascaded
    # away would take the answer with it.
    op.execute("ALTER TABLE evidence ADD COLUMN source_scan_id uuid;")


def downgrade() -> None:
    op.execute("ALTER TABLE evidence DROP COLUMN source_scan_id;")
