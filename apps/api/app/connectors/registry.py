"""Connector lookup by provider.

The one place that maps a stored ``provider`` string to an implementation.
Adding AWS later is a line in this dict plus a package under ``connectors/``.
"""

from types import ModuleType
from typing import Any

from app.connectors.aws.connector import AwsConnector
from app.connectors.aws.onboarding import AwsOnboarding
from app.connectors.azure import change_events as azure_change_events
from app.connectors.azure.connector import AzureConnector
from app.connectors.azure.onboarding import AzureOnboarding
from app.connectors.base import CloudConnector
from app.connectors.onboarding import ProviderOnboarding
from app.core.enums import Provider
from app.core.errors import NotConfigured

CONNECTORS: dict[Provider, type[CloudConnector]] = {
    Provider.AZURE: AzureConnector,
    Provider.AWS: AwsConnector,
}

# How a customer grants access to this provider, and how CloudGuard proves they
# did. Beside the connector lookup rather than inside the onboarding service,
# because the service is now provider-neutral and holding this map would be the
# one import that made it Azure-shaped again.
ONBOARDING: dict[Provider, type[ProviderOnboarding]] = {
    Provider.AZURE: AzureOnboarding,
    Provider.AWS: AwsOnboarding,
}

# The module that reads a provider's change events. Beside the connector lookup
# rather than in the service that debounces them, so the neutral half of
# change-triggered scanning holds no provider vocabulary at all -- not even the
# import that would fetch some.
CHANGE_FEEDS: dict[Provider, ModuleType] = {
    Provider.AZURE: azure_change_events,
}


def get_connector_class(provider: Provider | str) -> type[CloudConnector]:
    """The implementation for a provider, without building one.

    Separate from :func:`get_connector` because several questions -- what
    permissions this provider asks for, which evidence keys a category holds --
    are properties of the *provider* rather than of a connection to one, and
    answering them should not require the tenant and subscription ids a
    constructor wants.
    """
    provider = Provider(provider)
    implementation = CONNECTORS.get(provider)
    if implementation is None:
        raise NotConfigured(
            f"No connector is implemented for {provider.value}."
        )
    return implementation


def get_connector(provider: Provider | str, **kwargs: Any) -> CloudConnector:
    return get_connector_class(provider)(**kwargs)  # type: ignore[abstract]


def get_onboarding(provider: Provider | str) -> ProviderOnboarding:
    """How this provider's access is granted, checked and revoked.

    Separate from the connector because it is asked before one can exist: the
    whole point of onboarding is the period when there is no verified access to
    build a connector against.
    """
    resolved = Provider(provider)
    implementation = ONBOARDING.get(resolved)
    if implementation is None:
        raise NotConfigured(
            f"No onboarding flow is implemented for {resolved.value}."
        )
    return implementation()


def get_change_feed(provider: Provider | str) -> ModuleType:
    """How this provider says its environment changed.

    Separate from the connector because it is answered without one: a webhook
    arrives before any connection has been resolved, and deciding whether the
    delivery is worth reading must not require credentials to the environment it
    is about.
    """
    resolved = Provider(provider)
    feed = CHANGE_FEEDS.get(resolved)
    if feed is None:
        raise NotConfigured(
            f"No change feed is implemented for {resolved.value}."
        )
    return feed
