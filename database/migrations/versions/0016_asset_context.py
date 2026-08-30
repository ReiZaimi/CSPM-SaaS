"""What the customer says an asset is worth, and where every value came from.

Revision ID: 0016
Revises: 0015

Asset context -- criticality, data sensitivity, environment -- is the multiplier
that turns a finding into a risk. It has always been inferred from tags and
resource names, and two things were missing.

The first is provenance. A CRITICAL somebody typed into a tag and a CRITICAL
guessed from a resource name multiplied a finding identically, so a customer
asking why one thing outranks another could be shown the arithmetic and never
the input. The three ``*_source`` columns on ``cloud_resources`` record which it
was; the confidence attached to each source lives in code, derived from the
source, so the two can never disagree.

The second is the customer. Inference from tags is a guess, and a person saying
"this subscription is production" is not. ``context_declarations`` is the only
table in this schema holding something CloudGuard was *told* rather than
something it observed, which is why it is a table of its own rather than three
more columns on ``cloud_accounts``: a discovered subscription is a record of
what Azure said, discovery runs again, and the two kinds of fact have to stay
tellable apart.

A declaration is applied as a floor, never an override -- it can raise an
asset's criticality above what was inferred but not lower what the capture
showed -- so the worst a mistaken declaration can do is over-rank something.
That property is enforced in `app/context/engine.py`; nothing about it needs
a constraint here.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    # --- where each context value came from ------------------------------
    # Defaulting to 'none' rather than backfilling a guess. Rows written before
    # this migration were inferred by rules that are still in the tree, but
    # which of them fired for a given asset is not recoverable from the row --
    # and inventing a source would be the exact overclaim these columns exist
    # to prevent. The next scan writes the real answer.
    op.execute(
        """
        ALTER TABLE cloud_resources
            ADD COLUMN criticality_source      varchar(24) NOT NULL DEFAULT 'none',
            ADD COLUMN data_sensitivity_source varchar(24) NOT NULL DEFAULT 'none',
            ADD COLUMN environment_source      varchar(24) NOT NULL DEFAULT 'none';
        """
    )

    # --- what the customer declared --------------------------------------
    op.execute(
        """
        CREATE TABLE context_declarations (
            id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id  uuid NOT NULL
                             REFERENCES organizations(id) ON DELETE CASCADE,
            -- One declaration per subscription. CASCADE because a declaration
            -- about a subscription that is gone is not history worth keeping:
            -- it is a statement about something that no longer exists.
            cloud_account_id uuid NOT NULL UNIQUE
                             REFERENCES cloud_accounts(id) ON DELETE CASCADE,

            -- All three nullable: a customer who knows one thing should be able
            -- to say that one thing. NULL is "not declared", which is not the
            -- same as UNKNOWN -- UNKNOWN is CloudGuard's own answer, and this
            -- table only ever holds the customer's.
            environment      varchar(64),
            criticality      varchar(16),
            data_sensitivity varchar(16),

            -- Why. Shown beside the label rather than parsed: "holds the
            -- payroll export" is the sentence that stops the next person
            -- undoing this.
            note             text,

            -- Who. Not an FK: auth.users belongs to Supabase.
            declared_by_user_id uuid,
            declared_at      timestamptz NOT NULL DEFAULT now(),

            created_at       timestamptz NOT NULL DEFAULT now(),
            updated_at       timestamptz NOT NULL DEFAULT now(),

            CONSTRAINT ck_context_declarations_criticality
                CHECK (criticality IS NULL OR criticality IN
                       ('LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN')),
            CONSTRAINT ck_context_declarations_data_sensitivity
                CHECK (data_sensitivity IS NULL OR data_sensitivity IN
                       ('LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN'))
        );
        """
    )
    # How the pipeline reads them: every declaration this scan's subscriptions
    # have, in one statement rather than one per subscription.
    op.execute(
        """
        CREATE INDEX ix_context_declarations_org
            ON context_declarations (organization_id, cloud_account_id);
        """
    )

    op.execute("ALTER TABLE context_declarations ENABLE ROW LEVEL SECURITY;")
    for action, clause in (
        ("SELECT", "USING (app.is_member(organization_id))"),
        ("INSERT", "WITH CHECK (app.is_member(organization_id))"),
        (
            "UPDATE",
            "USING (app.is_member(organization_id)) "
            "WITH CHECK (app.is_member(organization_id))",
        ),
        ("DELETE", "USING (app.is_member(organization_id))"),
    ):
        op.execute(
            f"CREATE POLICY context_declarations_tenant_{action.lower()} "
            f"ON context_declarations FOR {action} {clause};"
        )
    # The worker reads these while scoring a scan. SELECT only, and that
    # asymmetry is the point: a declaration is the customer speaking, and a
    # background job that could write one would be CloudGuard putting words in
    # their mouth.
    op.execute(
        "CREATE POLICY context_declarations_worker_select "
        "ON context_declarations FOR SELECT TO cloudguard_worker "
        "USING (app.current_org() = organization_id);"
    )

    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON context_declarations TO authenticated;"
    )
    op.execute("GRANT SELECT ON context_declarations TO cloudguard_worker;")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS context_declarations;")
    op.execute(
        """
        ALTER TABLE cloud_resources
            DROP COLUMN IF EXISTS environment_source,
            DROP COLUMN IF EXISTS data_sensitivity_source,
            DROP COLUMN IF EXISTS criticality_source;
        """
    )
