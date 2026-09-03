"""Key vault: whether it survives, and who can reach it.

Both rules read the management plane, which is the whole of what the scanner
role is permitted to see. Nothing here knows what a vault holds, and the tests
say so as plainly as the rules do -- a product that can tell you your vault is
destroyable without being able to read a single secret in it is making a
stronger claim than one that can do both.

The absent-versus-false distinction is the interesting part. Azure omits
``enablePurgeProtection`` when it has never been set and returns
``enableSoftDelete`` as a value, so the two absences mean different things and
the rules read them differently. Getting that backwards would either report
nothing for most vaults in existence or report a gap CloudGuard invented.
"""

from typing import Any

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import Level, Provider, ResourceType, RuleState
from app.domain.resource import CloudResource
from app.rules.azure.secrets.key_vault import (
    AzureKeyVaultDeletionRule,
    AzureKeyVaultNetworkRule,
)
from app.rules.base import RuleContext

DELETION = AzureKeyVaultDeletionRule()
NETWORK = AzureKeyVaultNetworkRule()


def vault(**metadata: Any) -> CloudResource:
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id="/subscriptions/s/vaults/kv-prod",
        resource_type=ResourceType.KEY_VAULT,
        name="kv-prod",
        criticality=Level.HIGH,
        data_sensitivity=Level.HIGH,
        public_exposure=Level.UNKNOWN,
        metadata=metadata,
    )


def blind(key: AzureEvidence = AzureEvidence.KEY_VAULTS) -> RuleContext:
    return RuleContext(collection_errors={key.value: "Azure timed out"})


# ------------------------------------------------------------------- deletion
class TestKeyVaultDeletion:
    def test_a_vault_with_both_protections_passes(self) -> None:
        kv = vault(soft_delete=True, purge_protection=True)

        assert DELETION.evaluate(kv, RuleContext(resources=[kv])).state == RuleState.PASS

    def test_purge_protection_off_fails(self) -> None:
        kv = vault(soft_delete=True, purge_protection=False)

        result = DELETION.evaluate(kv, RuleContext(resources=[kv]))

        assert result.state == RuleState.FAIL
        assert "Purge protection is off" in result.evidence["problems"][0]

    def test_an_absent_purge_protection_is_read_as_off(self) -> None:
        """Azure omits the field rather than returning false when it has never
        been set. Reading that as UNKNOWN would report nothing for the
        overwhelming majority of vaults that genuinely lack it."""
        kv = vault(soft_delete=True)

        assert DELETION.evaluate(kv, RuleContext(resources=[kv])).state == RuleState.FAIL

    def test_soft_delete_off_fails_on_its_own(self) -> None:
        kv = vault(soft_delete=False, purge_protection=True)

        result = DELETION.evaluate(kv, RuleContext(resources=[kv]))

        assert result.state == RuleState.FAIL
        assert len(result.evidence["problems"]) == 1

    def test_a_vault_with_neither_field_is_unknown(self) -> None:
        """Both absent is a vault whose configuration never arrived, which is
        not the same as a vault configured badly."""
        kv = vault()

        assert (
            DELETION.evaluate(kv, RuleContext(resources=[kv])).state == RuleState.UNKNOWN
        )

    def test_a_failed_listing_is_unknown(self) -> None:
        kv = vault(soft_delete=False, purge_protection=False)

        assert DELETION.evaluate(kv, blind()).state == RuleState.UNKNOWN

    def test_no_resource_is_not_applicable(self) -> None:
        assert DELETION.evaluate(None, RuleContext()).state == RuleState.NOT_APPLICABLE


# -------------------------------------------------------------------- network
class TestKeyVaultNetwork:
    def test_a_vault_open_to_every_network_fails(self) -> None:
        kv = vault(network_default_action="Allow", public_network_access="Enabled")

        result = NETWORK.evaluate(kv, RuleContext(resources=[kv]))

        assert result.state == RuleState.FAIL

    def test_denying_by_default_passes(self) -> None:
        kv = vault(network_default_action="Deny", public_network_access="Enabled")

        assert NETWORK.evaluate(kv, RuleContext(resources=[kv])).state == RuleState.PASS

    def test_public_access_off_passes_whatever_the_acl_says(self) -> None:
        """A vault nothing can dial is not reachable, and the ACL in front of a
        closed door is not what makes it closed."""
        kv = vault(network_default_action="Allow", public_network_access="Disabled")

        assert NETWORK.evaluate(kv, RuleContext(resources=[kv])).state == RuleState.PASS

    def test_a_vault_on_rbac_scores_lower_than_one_on_access_policies(self) -> None:
        """Neither model narrows the network. But a vault still on legacy access
        policies has the weaker authorization in front of it, so an open network
        matters more there -- this steps down only for the stronger one."""
        rbac = vault(network_default_action="Allow", rbac_authorization=True)
        legacy = vault(network_default_action="Allow", rbac_authorization=False)

        assert NETWORK.evaluate(rbac, RuleContext(resources=[rbac])).exploitability == 3
        assert NETWORK.evaluate(legacy, RuleContext(resources=[legacy])).exploitability is None

    def test_no_network_configuration_is_unknown(self) -> None:
        kv = vault()

        assert (
            NETWORK.evaluate(kv, RuleContext(resources=[kv])).state == RuleState.UNKNOWN
        )

    def test_a_failed_listing_is_unknown(self) -> None:
        kv = vault(network_default_action="Allow")

        assert NETWORK.evaluate(kv, blind()).state == RuleState.UNKNOWN

    def test_no_resource_is_not_applicable(self) -> None:
        assert NETWORK.evaluate(None, RuleContext()).state == RuleState.NOT_APPLICABLE


# ------------------------------------------------------------- what it may read
class TestScopeOfTheEvidence:
    def test_neither_rule_asks_for_anything_but_the_vault_listing(self) -> None:
        """The permission behind these rules is the management-plane read. If a
        rule here ever needed a data-plane key, the role would have to ask for
        the ability to read secrets -- which is the one thing this product
        should never request."""
        for rule in (DELETION, NETWORK):
            assert rule.requires_evidence == (AzureEvidence.KEY_VAULTS,)
