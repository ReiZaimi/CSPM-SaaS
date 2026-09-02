"""Test fixtures.

Rule tests load normalized JSON from ``tests/fixtures`` and never touch a
database, a network or Azure. That is the point of the fixture strategy: a rule
test that needed a live tenant would not be a unit test, and CloudGuard
deliberately has no mock connector to stand in for one (AZURE_INTEGRATION.md
section 1).
"""

import os

# app.core.config validates the environment at import and refuses to load
# without a complete deployment configuration. The test suite runs against a
# throwaway database with no Supabase project behind it, so declare the test
# environment before any app module is imported. setdefault, so CI's own
# APP_ENV=test still wins and nothing is silently overridden.
os.environ.setdefault("APP_ENV", "test")
# The app never mints tokens, only verifies them, so the suite signs its own
# (tests/integration/test_api.py::issue_test_token) and needs a key to do it.
os.environ.setdefault("SUPABASE_JWT_SECRET", "test-jwt-secret")

import json
from pathlib import Path
from typing import Any

import pytest

from app.core.enums import Level, Provider, ResourceType
from app.domain.resource import CloudResource
from app.rules.base import RuleContext

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def load_fixture(category: str, name: str) -> dict[str, Any]:
    path = FIXTURE_ROOT / category / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Fixture not found: {path}")
    return json.loads(path.read_text())


def to_resource(raw: dict[str, Any]) -> CloudResource:
    return CloudResource(
        provider_resource_id=raw["provider_resource_id"],
        resource_type=ResourceType(raw["resource_type"]),
        name=raw["name"],
        provider=Provider(raw.get("provider", "azure")),
        region=raw.get("region"),
        environment=raw.get("environment"),
        criticality=Level(raw.get("criticality", "UNKNOWN")),
        data_sensitivity=Level(raw.get("data_sensitivity", "UNKNOWN")),
        public_exposure=Level(raw.get("public_exposure", "UNKNOWN")),
        metadata=raw.get("metadata", {}),
    )


def resource_from(category: str, name: str) -> CloudResource:
    return to_resource(load_fixture(category, name))


def make_context(
    *resources: CloudResource,
    relationships: dict[tuple[str, str], list[str]] | None = None,
    collection_errors: dict[str, str] | None = None,
    controls: dict | None = None,
) -> RuleContext:
    return RuleContext(
        resources=list(resources),
        relationships=relationships or {},
        controls=controls or {},
        # Keyed by evidence key, as the pipeline keys them.
        collection_errors={
            str(key): reason for key, reason in (collection_errors or {}).items()
        },
    )


@pytest.fixture
def fixture_loader():
    return resource_from
