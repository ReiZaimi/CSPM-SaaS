"""What a database is reachable from, and what it does with what it stores."""

from dataclasses import replace

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import Provider, ResourceType, RuleState
from app.domain.resource import CloudResource
from app.rules.azure.database.encryption import AzureDatabaseEncryptionRule
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

    def test_every_azure_tenant_is_not_the_whole_internet(self) -> None:
        """Both shapes fail, and they are not the same exposure. An attacker
        needs a subscription and a credential to use the Azure-services rule,
        rather than a scanner and an afternoon."""
        azure_only = resource_from("vulnerable", "sql_server_azure_services")
        everyone = resource_from("vulnerable", "sql_server_public")

        narrow = self.rule.evaluate(azure_only, make_context(azure_only))
        wide = self.rule.evaluate(everyone, make_context(everyone))

        assert self.rule.effective_exploitability(narrow) == 3
        assert self.rule.effective_exploitability(wide) == self.rule.exploitability
        assert self.rule.effective_exploitability(narrow) < self.rule.effective_exploitability(
            wide
        )

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


# ------------------------------------------------------ encryption at rest
def server_with(databases: list | None) -> CloudResource:
    metadata: dict = {"public_network_access": "Disabled"}
    if databases is not None:
        metadata["databases"] = databases
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id="/subscriptions/1/sql",
        resource_type=ResourceType.SQL_SERVER,
        name="sql-prod",
        metadata=metadata,
    )


class TestDatabaseEncryption:
    """AZ-DB-006. It passes for nearly everybody -- encryption has been on by
    default since 2017 -- and the value is in the two answers that are not a
    pass: a database somebody turned it off on, and a database nobody could
    read."""

    rule = AzureDatabaseEncryptionRule()

    def test_an_unencrypted_database_fails(self) -> None:
        server = server_with([{"database": "payments", "state": "Disabled"}])
        result = self.rule.evaluate(server, make_context(server))
        assert result.state == RuleState.FAIL
        assert result.evidence["unencrypted"][0]["database"] == "payments"

    def test_every_database_encrypted_passes(self) -> None:
        server = server_with(
            [
                {"database": "payments", "state": "Enabled"},
                {"database": "reporting", "state": "Enabled"},
            ]
        )
        assert (
            self.rule.evaluate(server, make_context(server)).state is RuleState.PASS
        )

    def test_a_server_whose_databases_could_not_be_listed_is_unknown(self) -> None:
        """A role predating v6 produces exactly this. Reading it as "no
        databases, therefore nothing unencrypted" would be a pass built on a
        call that was refused."""
        server = server_with(None)
        assert (
            self.rule.evaluate(server, make_context(server)).state is RuleState.UNKNOWN
        )

    def test_one_unreadable_database_is_unknown_not_a_pass(self) -> None:
        server = server_with(
            [
                {"database": "payments", "state": "Enabled"},
                {"database": "archive", "state": None},
            ]
        )
        assert (
            self.rule.evaluate(server, make_context(server)).state is RuleState.UNKNOWN
        )

    def test_an_unreadable_database_travels_with_a_failure(self) -> None:
        """A server with one unencrypted database and one unreadable is worse
        than the finding alone says, and hiding that behind the failure would
        be the same overclaim pointed the other way."""
        server = server_with(
            [
                {"database": "payments", "state": "Disabled"},
                {"database": "archive", "state": None},
            ]
        )
        result = self.rule.evaluate(server, make_context(server))
        assert result.state == RuleState.FAIL
        assert result.evidence["unreadable"] == ["archive"]

    def test_a_failed_encryption_reading_is_unknown(self) -> None:
        server = server_with([{"database": "payments", "state": "Enabled"}])
        context = make_context(
            server, collection_errors={AzureEvidence.SQL_TDE.value: "403"}
        )
        assert self.rule.evaluate(server, context).state is RuleState.UNKNOWN
