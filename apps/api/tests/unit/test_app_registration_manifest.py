"""The committed manifest is what actually gets deployed.

``REQUIRED_GRAPH_PERMISSIONS`` is the source of truth in code;
``infrastructure/azure/app-registration.json`` is the file
``apply-app-registration.sh`` hands to ``az ad app update``. If they disagree,
the permission a new rule needs is one no customer has ever been asked to grant
-- and the symptom arrives months later as a 403 inside one collection
category, which is exactly how the identity gap went unnoticed.

CI diffs the two as well. This test exists so the failure is also visible to
someone running the suite locally, before the push.
"""

import json
from pathlib import Path

from app.connectors.azure.auth import app_registration_manifest

MANIFEST = (
    Path(__file__).resolve().parents[4]
    / "infrastructure"
    / "azure"
    / "app-registration.json"
)


def test_the_committed_manifest_exists() -> None:
    assert MANIFEST.exists(), f"{MANIFEST} is missing; the deploy script reads it"


def test_the_committed_manifest_matches_the_code() -> None:
    assert json.loads(MANIFEST.read_text()) == app_registration_manifest(), (
        "infrastructure/azure/app-registration.json is out of date. Regenerate "
        "it, re-run apply-app-registration.sh, and have every connected tenant "
        "consent again -- consent does not extend to permissions added after it."
    )
