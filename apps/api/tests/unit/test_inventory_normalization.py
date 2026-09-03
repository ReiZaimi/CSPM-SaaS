"""The resources CloudGuard does not check, said out loud.

The inventory was collected on every scan, stored in every snapshot, and read
by nothing -- while the asset list showed only the ten-odd types the connector
models in detail. A customer with a subscription full of App Services saw a tidy
inventory of storage and virtual machines and nothing to say most of what they
own was missing from it. Silence read as coverage.

Two properties carry the whole design. Nothing is counted twice: the inventory
covers the same storage accounts the storage listing already produced, in far
less detail, and two rows for one asset would be an inventory that miscounts and
a graph holding the same thing twice. And nothing is judged: these carry
``ResourceType.UNKNOWN``, no rule's ``applies_to`` names it, so none of them can
become a PASS nobody earned.
"""

from typing import Any

from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Level, Provider, ResourceType

SUB = "/subscriptions/sub-1"


def row(
    name: str,
    azure_type: str,
    *,
    resource_id: str | None = None,
    tags: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "id": resource_id or f"{SUB}/resourceGroups/rg/providers/{azure_type}/{name}",
        "name": name,
        "type": azure_type,
        "kind": None,
        "location": "westeurope",
        "resourceGroup": "rg",
        "subscriptionId": "sub-1",
        "tags": tags or {},
    }


def normalize(data: dict[str, Any]):
    snapshot = RawSnapshot(
        provider=Provider.AZURE,
        tenant_id="t",
        subscription_id="sub-1",
        data=data,
    )
    return AzureNormalizer().normalize(snapshot)


def unchecked(state) -> list:
    return [r for r in state.resources if r.resource_type == ResourceType.UNKNOWN]


class TestUncheckedResourcesAreListed:
    def test_a_type_no_rule_covers_becomes_an_asset(self) -> None:
        state = normalize({"resources": [row("api", "Microsoft.Web/sites")]})

        assets = unchecked(state)
        assert len(assets) == 1
        assert assets[0].name == "api"
        assert assets[0].metadata["azure_type"] == "Microsoft.Web/sites"

    def test_it_is_marked_unchecked_rather_than_left_to_be_inferred(self) -> None:
        """A consumer should not have to know that UNKNOWN means unchecked."""
        state = normalize({"resources": [row("api", "Microsoft.Web/sites")]})

        assert unchecked(state)[0].metadata["unchecked"] is True

    def test_exposure_stays_unknown_rather_than_low(self) -> None:
        """Resource Graph's projection excludes `properties` on purpose, so
        there is no configuration here to establish exposure from. LOW would be
        reassurance CloudGuard did not earn."""
        state = normalize({"resources": [row("api", "Microsoft.Web/sites")]})

        assert unchecked(state)[0].public_exposure == Level.UNKNOWN

    def test_tags_still_classify_it(self) -> None:
        """Context comes from tags for these exactly as it does for a modelled
        asset. Not being checked is not a reason to know less about it."""
        state = normalize(
            {"resources": [row("api", "Microsoft.Web/sites", tags={"env": "production"})]}
        )

        assert unchecked(state)[0].environment == "production"

    def test_a_row_with_no_id_is_skipped(self) -> None:
        state = normalize({"resources": [{"name": "nameless", "type": "X"}]})

        assert unchecked(state) == []


class TestNothingIsCountedTwice:
    def test_a_storage_account_the_listing_produced_is_not_added_again(self) -> None:
        """The inventory sees the same account, with less detail. The listing's
        version is the one with the configuration a rule reads."""
        account_id = f"{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa"
        state = normalize(
            {
                "storage_accounts": [
                    {
                        "id": account_id,
                        "name": "sa",
                        "location": "westeurope",
                        "properties": {"allowBlobPublicAccess": False},
                    }
                ],
                "resources": [
                    row("sa", "Microsoft.Storage/storageAccounts", resource_id=account_id)
                ],
            }
        )

        matching = [
            r for r in state.resources if r.provider_resource_id == account_id
        ]
        assert len(matching) == 1
        assert matching[0].resource_type == ResourceType.STORAGE_ACCOUNT

    def test_a_repeated_inventory_row_becomes_one_asset(self) -> None:
        """Resource Graph pages a stable ordered query, and a repeated row would
        otherwise be a repeated asset."""
        duplicate = row("api", "Microsoft.Web/sites")
        state = normalize({"resources": [duplicate, dict(duplicate)]})

        assert len(unchecked(state)) == 1

    def test_the_modelled_and_the_unchecked_live_in_one_list(self) -> None:
        """Which is the point: the asset list stops being a list of what
        CloudGuard happens to model."""
        state = normalize(
            {
                "storage_accounts": [
                    {"id": f"{SUB}/sa", "name": "sa", "properties": {}}
                ],
                "resources": [
                    row("api", "Microsoft.Web/sites"),
                    row("cache", "Microsoft.Cache/Redis"),
                ],
            }
        )

        assert len(unchecked(state)) == 2
        assert any(
            r.resource_type == ResourceType.STORAGE_ACCOUNT for r in state.resources
        )


class TestNothingJudgesThem:
    def test_no_rule_applies_to_an_unchecked_resource(self) -> None:
        """The load-bearing property. A rule that matched one would be reaching
        a verdict about configuration CloudGuard never collected."""
        from app.rules.registry import RULE_REGISTRY

        state = normalize({"resources": [row("api", "Microsoft.Web/sites")]})
        asset = unchecked(state)[0]

        assert [rule.rule_id for rule in RULE_REGISTRY if rule.matches(asset)] == []
