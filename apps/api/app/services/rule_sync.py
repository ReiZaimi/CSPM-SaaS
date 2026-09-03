"""Sync the Python rule registry into the ``rules`` read-mirror.

The registry is the source of truth. The table exists so the API and UI can join
rule metadata onto findings without importing rule code, and so a finding can
name a rule that has since changed. Runs at startup with the owner connection —
``authenticated`` deliberately has no write access to this table.
"""

from sqlalchemy import select

from app.core.db import service_session
from app.models.rule import Rule
from app.rules.registry import RULE_REGISTRY


async def sync_rules_to_database() -> int:
    async with service_session() as session:
        existing = {
            row.rule_id: row for row in (await session.execute(select(Rule))).scalars().all()
        }

        for rule in RULE_REGISTRY:
            values = {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "description": rule.description,
                "category": rule.category,
                "provider": rule.provider.value,
                "severity": rule.severity.value,
                "version": rule.version,
                "exploitability": rule.exploitability,
                "scope": rule.scope.value,
                "applies_to": [t.value for t in rule.applies_to],
                "enabled": True,
                "remediation": rule.remediation,
                "estimated_effort_minutes": rule.estimated_effort_minutes,
                "rationale": rule.rationale,
                "compliance_mappings": rule.compliance_mappings,
                # Mirrored so the compliance view can follow a control back to
                # the readings behind it without importing rule code.
                "requires_evidence": [key.value for key in rule.requires_evidence],
            }

            row = existing.get(rule.rule_id)
            if row is None:
                session.add(Rule(**values))
            else:
                for key, value in values.items():
                    setattr(row, key, value)

        # A rule deleted from the registry is disabled rather than removed:
        # findings it raised in the past still reference it.
        registry_ids = {r.rule_id for r in RULE_REGISTRY}
        for rule_id, row in existing.items():
            if rule_id not in registry_ids:
                row.enabled = False

        await session.commit()
        return len(RULE_REGISTRY)
