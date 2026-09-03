"""Whether a database keeps a record of who read it.

Auditing is off by default on every Azure SQL server, so this is a setting most
customers have never turned on rather than one they turned off. Without it a
database breach is unbounded by evidence: there is no way to tell whether an
attacker read one row or every row.

Two failure modes, deliberately separate. Off is a switch. On-with-no-
destination is the setting people believe they have and do not, and the fix is
a destination rather than a switch -- so the rule says which it found.
"""

from typing import Any

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import Level, Provider, ResourceType, RuleState
from app.domain.resource import CloudResource
from app.rules.azure.database.public_access import AzureDatabaseAuditingRule
from app.rules.base import RuleContext

RULE = AzureDatabaseAuditingRule()


def server(auditing: Any, **extra: Any) -> CloudResource:
    metadata: dict[str, Any] = {"public_network_access": "Enabled", **extra}
    metadata["auditing"] = auditing
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id="/subscriptions/s/servers/sql-prod",
        resource_type=ResourceType.SQL_SERVER,
        name="sql-prod",
        criticality=Level.HIGH,
        data_sensitivity=Level.HIGH,
        public_exposure=Level.HIGH,
        metadata=metadata,
    )


def auditing(**fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "state": "Enabled",
        "retention_days": 90,
        "storage_endpoint": None,
        "log_analytics_enabled": None,
        "audit_actions": [],
    }
    base.update(fields)
    return base


def judge(resource: CloudResource) -> RuleState:
    return RULE.evaluate(resource, RuleContext(resources=[resource])).state


class TestDatabaseAuditing:
    def test_auditing_to_log_analytics_passes(self) -> None:
        assert judge(server(auditing(log_analytics_enabled=True))) == RuleState.PASS

    def test_auditing_to_storage_passes(self) -> None:
        """Where the records go is the customer's choice. That they go
        somewhere is the finding."""
        assert (
            judge(server(auditing(storage_endpoint="https://logs.blob.core.windows.net")))
            == RuleState.PASS
        )

    def test_auditing_switched_off_fails(self) -> None:
        result = RULE.evaluate(
            server(auditing(state="Disabled")),
            RuleContext(resources=[server(auditing(state="Disabled"))]),
        )

        assert result.state == RuleState.FAIL
        assert result.evidence["problems"] == ["Auditing is not enabled"]

    def test_auditing_on_with_nowhere_to_write_fails_differently(self) -> None:
        """The setting people believe they have. Reported apart from 'off'
        because the fix is a destination, not a switch."""
        result = RULE.evaluate(
            server(auditing()), RuleContext(resources=[server(auditing())])
        )

        assert result.state == RuleState.FAIL
        assert result.evidence["problems"] == [
            "Auditing is enabled but has no destination"
        ]
        assert "writes nowhere" in (result.message or "")

    def test_settings_that_could_not_be_read_are_unknown(self) -> None:
        """The per-server call failed, or the deployed role predates v4 and
        answered 403. A server we could not ask is not a server without
        auditing, and this is the case the role upgrade creates."""
        assert judge(server(None)) == RuleState.UNKNOWN

    def test_the_unknown_message_names_the_role_as_a_possible_cause(self) -> None:
        """Otherwise every v3 customer sees an unexplained UNKNOWN on every SQL
        server they own, with nothing to act on."""
        result = RULE.evaluate(server(None), RuleContext(resources=[server(None)]))

        assert "scanner role" in (result.message or "")

    def test_a_failed_server_listing_is_unknown(self) -> None:
        sub = server(auditing(state="Disabled"))
        context = RuleContext(
            resources=[sub],
            collection_errors={AzureEvidence.SQL_SERVERS.value: "timeout"},
        )

        assert RULE.evaluate(sub, context).state == RuleState.UNKNOWN

    def test_no_resource_is_not_applicable(self) -> None:
        assert RULE.evaluate(None, RuleContext()).state == RuleState.NOT_APPLICABLE


class TestItPairsWithExposure:
    def test_the_evidence_carries_whether_the_server_is_also_reachable(self) -> None:
        """A public endpoint with no audit trail is the worst pairing in the
        catalogue. AZ-DB-001 raises the other half; this one carries the fact
        so the two can be read together."""
        result = RULE.evaluate(
            server(auditing(state="Disabled")),
            RuleContext(resources=[server(auditing(state="Disabled"))]),
        )

        assert result.evidence["public_network_access"] == "Enabled"

    def test_it_declares_no_expected_state_and_says_why(self) -> None:
        """Two conditions on one nested setting, and the three comparisons a
        declaration may use express neither. A declaration saying only 'state
        is Enabled' would have a customer satisfy exactly what they were shown,
        still audit to nowhere, and watch the finding stay open."""
        spec = RULE.remediation_spec

        assert spec is not None
        assert spec.expected == ()
        assert spec.cli
        assert "worse than none" in spec.notes
        assert spec.enforceable is False


class TestTheKeysAreSeparate:
    """A refused auditing read must cost this rule and no other.

    The two SQL readings fail independently: a scanner role deployed before v4
    reads servers and firewall rules perfectly well and is refused the auditing
    call. Folded into one evidence key, that 403 degraded AZ-DB-001 as well --
    over a call it never reads. That is a gap CloudGuard invented rather than
    found, which is exactly what ``requires_evidence`` exists to prevent, and
    the fix is the same one applied a layer up: name the thing you depend on,
    not the category it happens to sit in.
    """

    def test_this_rule_declares_both_readings_it_rests_on(self) -> None:
        assert set(RULE.requires_evidence) == {
            AzureEvidence.SQL_SERVERS,
            AzureEvidence.SQL_AUDITING,
        }

    def test_the_public_access_rule_does_not_depend_on_auditing(self) -> None:
        from app.rules.azure.database.public_access import AzurePublicDatabaseRule

        assert AzureEvidence.SQL_AUDITING not in AzurePublicDatabaseRule.requires_evidence

    def test_a_refused_auditing_read_leaves_the_public_access_verdict_standing(
        self,
    ) -> None:
        """The behaviour, not just the declaration. Same context, two rules,
        and only the one that reads the refused call loses its answer."""
        from app.rules.azure.database.public_access import AzurePublicDatabaseRule

        sql = server(
            None,
            public_network_access="Enabled",
            firewall_rules=[
                {
                    "name": "open",
                    "start_ip_address": "0.0.0.0",
                    "end_ip_address": "255.255.255.255",
                }
            ],
        )
        context = RuleContext(
            resources=[sql],
            collection_errors={AzureEvidence.SQL_AUDITING.value: "403 denied"},
        )

        assert RULE.evaluate(sql, context).state == RuleState.UNKNOWN
        assert (
            AzurePublicDatabaseRule().evaluate(sql, context).state == RuleState.FAIL
        )

