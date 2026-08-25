"""Connector lookup by provider.

The one place that maps a stored ``provider`` string to an implementation.
Adding AWS later is a line in this dict plus a package under ``connectors/``.
"""

from typing import Any

from app.connectors.azure.connector import AzureConnector
from app.connectors.base import CloudConnector
from app.core.enums import Provider
from app.core.errors import NotConfigured


def get_connector(provider: Provider | str, **kwargs: Any) -> CloudConnector:
    provider = Provider(provider)
    if provider == Provider.AZURE:
        return AzureConnector(**kwargs)
    raise NotConfigured(
        f"No connector is implemented for {provider.value}. "
        "Azure is the only supported provider in this release."
    )
