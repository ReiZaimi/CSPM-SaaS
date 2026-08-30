"""Evidence: one row per reading, one stored copy of what it produced.

Two problems these pin, both about the same shape. A finding pointed at a scan,
and a scan pointed at one blob holding every listing it had read -- so "where
did this come from" was answerable only by a person opening the blob. And every
scan stored that whole blob again, so a customer scanning daily whose network
security groups have not changed in a month kept thirty identical copies.

The reconstruction test is the important one. ``cloud_snapshots`` is still what
replay reads, and evidence is written beside it rather than instead of it. The
precondition for ever flipping that round is that the per-reading payloads add
back up to the capture exactly -- so it is checked now, while both exist.
"""

from app.connectors.azure.evidence import AzureEvidence
from app.connectors.collection import CoverageReport, TaskResult
from app.connectors.evidence import EvidenceCategory
from app.core.enums import TaskOutcome
from app.services.scanner import _digest


def result(key: AzureEvidence, outcome: TaskOutcome = TaskOutcome.COMPLETE) -> TaskResult:
    return TaskResult(
        key=key,
        category=key.category,
        outcome=outcome,
        permissions=("Microsoft.Storage/storageAccounts/read",),
    )


# ------------------------------------------------------------------ hashing
def test_the_same_content_hashes_the_same_whatever_the_key_order() -> None:
    """Otherwise the deduplication is decorative.

    Two scans reading the same environment must produce the same digest, and
    dict ordering is not something a provider promises.
    """
    first = {"storage_accounts": [{"id": "/a", "name": "one", "kind": "StorageV2"}]}
    second = {"storage_accounts": [{"kind": "StorageV2", "name": "one", "id": "/a"}]}

    assert _digest(first)[0] == _digest(second)[0]


def test_different_content_hashes_differently() -> None:
    a = _digest({"storage_accounts": [{"id": "/a"}]})[0]
    b = _digest({"storage_accounts": [{"id": "/b"}]})[0]
    assert a != b


def test_the_digest_reports_the_size_it_hashed() -> None:
    """The number retention reasons about, so it has to be the stored bytes
    rather than an estimate of them."""
    digest, size = _digest({"storage_accounts": []})
    assert len(digest) == 64
    assert size == len('{"storage_accounts":[]}')


# ------------------------------------------------------- payloads and coverage
def test_a_run_keeps_each_reading_apart_as_well_as_merged() -> None:
    """The merged view is what the normalizer reads; the split view is what
    evidence is stored by. Both, from one run."""
    report = CoverageReport()
    report.record(result(AzureEvidence.STORAGE_ACCOUNTS), {"storage_accounts": [1]})
    report.record(result(AzureEvidence.VIRTUAL_MACHINES), {"virtual_machines": [2]})

    assert report.payloads == {
        "storage_accounts": {"storage_accounts": [1]},
        "virtual_machines": {"virtual_machines": [2]},
    }


def test_the_payloads_reconstruct_the_capture_exactly() -> None:
    """The precondition for evidence ever replacing the snapshot.

    Replay reads ``cloud_snapshots`` and must keep doing so until this holds
    against real scans. If the readings did not add back up to the capture, a
    flip would silently drop whatever fell between them.
    """
    merged: dict = {}
    report = CoverageReport()
    for key, payload in (
        (AzureEvidence.STORAGE_ACCOUNTS, {"storage_accounts": [{"id": "/s"}]}),
        (AzureEvidence.VIRTUAL_MACHINES, {"virtual_machines": [{"id": "/v"}]}),
        # One task, two payload keys: the directory task produces both the role
        # map and the authentication methods read from it.
        (
            AzureEvidence.USER_ROLE_MAP,
            {"user_role_map": {"u": ["Global Administrator"]}, "authentication_methods": {}},
        ),
    ):
        merged.update(payload)
        report.record(result(key), payload)

    rebuilt: dict = {}
    for payload in report.payloads.values():
        rebuilt.update(payload)

    assert rebuilt == merged


def test_a_failed_reading_stores_no_payload() -> None:
    """A hash of nothing would claim there was something to point at."""
    report = CoverageReport()
    report.record(result(AzureEvidence.STORAGE_ACCOUNTS, TaskOutcome.FAILED), {})

    assert "storage_accounts" in report.results
    assert report.payloads == {}


# ---------------------------------------------------------------- provenance
def test_coverage_records_the_permissions_a_reading_was_made_under() -> None:
    """Recorded rather than looked up later: a role can be redeployed between
    the scan and the question, and what matters is what the read needed at the
    moment it was made."""
    report = CoverageReport()
    report.record(result(AzureEvidence.STORAGE_ACCOUNTS), {"storage_accounts": []})

    entry = report.to_json()["storage_accounts"]
    assert entry["permissions"] == ["Microsoft.Storage/storageAccounts/read"]
    assert entry["category"] == EvidenceCategory.STORAGE.value


def test_the_payloads_stay_out_of_the_serialized_coverage() -> None:
    """Coverage travels inside the snapshot, which already holds the data.
    Serializing the payloads there would write every listing twice."""
    report = CoverageReport()
    report.record(result(AzureEvidence.STORAGE_ACCOUNTS), {"storage_accounts": [1, 2, 3]})

    serialized = report.to_json()["storage_accounts"]
    assert "payload" not in serialized
    assert set(serialized) == {
        "category",
        "outcome",
        "detail",
        "item_count",
        "permissions",
    }
