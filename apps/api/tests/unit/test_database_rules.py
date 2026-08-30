"""AZ-DB-001."""

from dataclasses import replace

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import RuleState
from app.rules.azure.database.public_access import AzurePublicDatabaseRule
from tests.conftest import make_context, resource_from


class TestPublicDatabase:
    rule = AzurePublicDatabaseRule()

    def test_open_firewall_detected(self) -> None:
        server = resource_from("vulnerable", "sql_server_public")
        result = self.rule.evaluate(server, make_context(server))
        assert result.state == RuleState.FAIL
        assert result.evidence["offending_firewall_rules"][0]["name"] == "AllowAll"

    def test_allow_azure_services_detected(self) -> None:
        """0.0.0.0-0.0.0.0 means every Azure tenant, not just this one."""
        server = resource_from("vulnerable", "sql_server_azure_services")
        result = self.rule.evaluate(server, make_context(server))
        assert result.state == RuleState.FAIL
        assert "other tenants" in " ".join(result.evidence["problems"])

    def test_private_server_passes(self) -> None:
        server = resource_from("secure", "sql_server_private")
        assert self.rule.evaluate(server, make_context(server)).state == RuleState.PASS

    def test_public_but_firewalled_passes(self) -> None:
        """Public access restricted to a specific office range is defensible."""
        server = resource_from("secure", "sql_server_restricted_firewall")
        assert self.rule.evaluate(server, make_context(server)).state == RuleState.PASS

    def test_public_with_no_firewall_rules_fails(self) -> None:
        server = resource_from("secure", "sql_server_restricted_firewall")
        wide_open = replace(server, metadata={**server.metadata, "firewall_rules": []})
        result = self.rule.evaluate(wide_open, make_context(wide_open))
        assert result.state == RuleState.FAIL

    def test_unknown_when_config_missing(self) -> None:
        server = resource_from("unknown", "sql_server_config_missing")
        assert self.rule.evaluate(server, make_context(server)).state == RuleState.UNKNOWN

    def test_unknown_when_database_collection_failed(self) -> None:
        server = resource_from("vulnerable", "sql_server_public")
        ctx = make_context(server, collection_errors={AzureEvidence.SQL_SERVERS: "403 Forbidden"})
        assert self.rule.evaluate(server, ctx).state == RuleState.UNKNOWN
