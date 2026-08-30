"""Connector lookup by provider.

The one place that maps a stored ``provider`` string to an implementation.
Adding AWS later is a line in this dict plus a package under ``connectors/``.
"""

from types import ModuleType
from typing import Any

from app.connectors.azure import change_events as azure_change_events
from app.connectors.azure.connector import AzureConnector
from app.connectors.base import CloudConnector
from app.core.enums import Provider
from app.core.errors import NotConfigured

CONNECTORS: dict[Provider, type[CloudConnector]] = {
    Provider.AZURE: AzureConnector,
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
            f"No connector is implemented for {provider.value}. "
            "Azure is the only supported provider in this release."
        )
    return implementation


def get_connector(provider: Provider | str, **kwargs: Any) -> CloudConnector:
    return get_connector_class(provider)(**kwargs)  # type: ignore[abstract]


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
