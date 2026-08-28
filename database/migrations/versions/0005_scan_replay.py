"""Replaying a stored snapshot.

Revision ID: 0005
Revises: 0004

Every scan has always written its raw capture to ``cloud_snapshots`` before
interpreting any of it, on the promise that the scan could be re-evaluated
later against better rules. Nothing ever read one back. These two columns are
what turns that promise into a feature.

``replay_of_scan_id`` points at the scan whose snapshot was re-evaluated. It is
``ON DELETE SET NULL`` for the same reason ``findings.scan_id`` is: deleting a
scan prunes an execution log, and must not cascade into records that are about
the environment rather than about the run.

``evaluation_only`` is the safety interlock, and the more important of the two.
A replay of a month-old snapshot that now produces PASS where a finding was
FAIL would otherwise reach the auto-resolve path and stamp that finding
"verified fixed" -- on the strength of data collected before anyone knew the
rule existed. So only a replay of the newest snapshot for an account may touch
findings at all; older ones record coverage, report what the rules would have
found, and write nothing. This column is how a scan row says which of the two
it was, months later, to someone asking why the numbers differ.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE scans
          ADD COLUMN replay_of_scan_id uuid
              REFERENCES scans(id) ON DELETE SET NULL,
          ADD COLUMN evaluation_only boolean NOT NULL DEFAULT false;
        """
    )
    # Replays are looked up by what they replayed, both to show a source scan's
    # re-evaluations and to stop a snapshot being replayed twice concurrently.
    op.execute(
        """
        CREATE INDEX ix_scans_replay_of_scan_id
            ON scans (replay_of_scan_id)
            WHERE replay_of_scan_id IS NOT NULL;
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_scans_replay_of_scan_id;")
    op.execute(
        """
        ALTER TABLE scans
          DROP COLUMN IF EXISTS replay_of_scan_id,
          DROP COLUMN IF EXISTS evaluation_only;
        """
    )
