"""AZ-STO-001 / AZ-STO-002."""

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import RuleState
from app.rules.azure.storage.public_access import (
    AzurePublicStorageRule,
    AzureStorageEncryptionRule,
)
from tests.conftest import make_context, resource_from


class TestPublicStorage:
    rule = AzurePublicStorageRule()

    def test_public_storage_detected(self) -> None:
        storage = resource_from("vulnerable", "storage_public")
        result = self.rule.evaluate(storage, make_context(storage))
        assert result.state == RuleState.FAIL
        assert result.evidence["allow_blob_public_access"] is True
        assert "customer-exports" in result.evidence["public_containers"]

    def test_locked_down_storage_passes(self) -> None:
        storage = resource_from("secure", "storage_locked_down")
        assert self.rule.evaluate(storage, make_context(storage)).state == RuleState.PASS

    def test_private_blob_with_open_network_still_fails(self) -> None:
        """Blob access off but network default Allow is still public exposure."""
        from dataclasses import replace

        storage = resource_from("secure", "storage_locked_down")
        opened = replace(
            storage,
            metadata={**storage.metadata, "network_default_action": "Allow"},
        )
        assert self.rule.evaluate(opened, make_context(opened)).state == RuleState.FAIL

    def test_anonymous_access_carries_the_rule_tag(self) -> None:
        """No credential, no exploit: the data is handed to whoever asks. This
        is the worst case the rule's tag describes."""
        storage = resource_from("vulnerable", "storage_public")
        result = self.rule.evaluate(storage, make_context(storage))

        assert result.exploitability is None
        assert self.rule.effective_exploitability(result) == self.rule.exploitability

    def test_an_open_network_without_anonymous_access_scores_lower(self) -> None:
        """Two different failures wear this one rule id. Reachable from every
        network still needs a key or a SAS token, which is an attacker who
        already has a credential -- a materially different afternoon from one
        where the blobs are simply served."""
        from dataclasses import replace

        storage = resource_from("secure", "storage_locked_down")
        opened = replace(
            storage,
            metadata={**storage.metadata, "network_default_action": "Allow"},
        )
        result = self.rule.evaluate(opened, make_context(opened))

        assert result.state == RuleState.FAIL
        assert self.rule.effective_exploitability(result) == 3
        assert self.rule.exploitability > 3

    def test_unknown_when_config_missing(self) -> None:
        storage = resource_from("unknown", "storage_config_missing")
        assert self.rule.evaluate(storage, make_context(storage)).state == RuleState.UNKNOWN

    def test_unknown_when_storage_collection_failed(self) -> None:
        storage = resource_from("vulnerable", "storage_public")
        ctx = make_context(
            storage,
            collection_errors={AzureEvidence.STORAGE_ACCOUNTS: "API timeout"},
        )
        assert self.rule.evaluate(storage, ctx).state == RuleState.UNKNOWN


class TestStorageEncryption:
    rule = AzureStorageEncryptionRule()

    def test_http_and_old_tls_detected(self) -> None:
        storage = resource_from("vulnerable", "storage_weak_tls")
        result = self.rule.evaluate(storage, make_context(storage))
        assert result.state == RuleState.FAIL
        assert len(result.evidence["problems"]) == 2

    def test_secure_transport_passes(self) -> None:
        storage = resource_from("secure", "storage_locked_down")
        assert self.rule.evaluate(storage, make_context(storage)).state == RuleState.PASS

    def test_public_storage_with_good_tls_passes_this_rule(self) -> None:
        """Separate concerns: STO-002 is about transport, not public access."""
        storage = resource_from("vulnerable", "storage_public")
        assert self.rule.evaluate(storage, make_context(storage)).state == RuleState.PASS

    def test_unknown_when_config_missing(self) -> None:
        storage = resource_from("unknown", "storage_config_missing")
        assert self.rule.evaluate(storage, make_context(storage)).state == RuleState.UNKNOWN
