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

import hashlib
import zlib
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.connectors.azure.evidence import AzureEvidence
from app.connectors.azure.plan import STORAGE_ENDPOINT
from app.connectors.collection import CoverageReport, TaskResult
from app.connectors.evidence import EvidenceCategory
from app.core.enums import TaskOutcome
from app.core.errors import SnapshotUnavailable
from app.core.payloads import compress, decompress, digest
from app.services.scanner import _rebuild_capture


def result(key: AzureEvidence, outcome: TaskOutcome = TaskOutcome.COMPLETE) -> TaskResult:
    return TaskResult(
        key=key,
        category=key.category,
        outcome=outcome,
        permissions=("Microsoft.Storage/storageAccounts/read",),
        endpoints=(STORAGE_ENDPOINT,),
    )


# ------------------------------------------------------------------ hashing
def test_the_same_content_hashes_the_same_whatever_the_key_order() -> None:
    """Otherwise the deduplication is decorative.

    Two scans reading the same environment must produce the same digest, and
    dict ordering is not something a provider promises.
    """
    first = {"storage_accounts": [{"id": "/a", "name": "one", "kind": "StorageV2"}]}
    second = {"storage_accounts": [{"kind": "StorageV2", "name": "one", "id": "/a"}]}

    assert digest(first)[0] == digest(second)[0]


def test_different_content_hashes_differently() -> None:
    a = digest({"storage_accounts": [{"id": "/a"}]})[0]
    b = digest({"storage_accounts": [{"id": "/b"}]})[0]
    assert a != b


def test_the_digest_reports_the_size_it_hashed() -> None:
    """The number retention reasons about, so it has to be the stored bytes
    rather than an estimate of them."""
    content_hash, size = digest({"storage_accounts": []})
    assert len(content_hash) == 64
    assert size == len('{"storage_accounts":[]}')


# -------------------------------------------------------------- compression
def test_a_payload_survives_the_round_trip_through_compression() -> None:
    """The stored form is bytes now, not a JSONB tree. Everything downstream
    reads the payload back whole, so the only thing that matters about the
    encoding is that it is exactly reversible."""
    payload = {
        "storage_accounts": [
            {"id": f"/subscriptions/s/rg/storage/{n}", "properties": {"https": True}}
            for n in range(50)
        ]
    }

    assert decompress(compress(payload)) == payload


def test_the_stored_bytes_are_the_bytes_the_hash_was_taken_over() -> None:
    """What makes a stored payload checkable against the hash it is filed
    under. Compressing a fresh serialization would round-trip to an equal dict
    and a different byte string, and the check would then be a coin toss
    between a real corruption and a whitespace difference."""
    payload = {"storage_accounts": [{"name": "one", "id": "/a"}]}

    inflated = zlib.decompress(compress(payload))

    assert hashlib.sha256(inflated).hexdigest() == digest(payload)[0]


def test_compression_actually_shrinks_a_provider_listing() -> None:
    """The reason this exists. Azure listings are the same twenty key names and
    the same resource-group prefix repeated per row, which is the input zlib is
    best at -- a guard against a future encoding change that quietly stores
    them at full size."""
    payload = {
        "network_security_groups": [
            {
                "id": f"/subscriptions/abc/resourceGroups/prod/providers/"
                f"Microsoft.Network/networkSecurityGroups/nsg-{n}",
                "location": "westeurope",
                "properties": {"securityRules": [], "provisioningState": "Succeeded"},
            }
            for n in range(200)
        ]
    }

    assert len(compress(payload)) * 10 < digest(payload)[1]


def test_an_empty_payload_still_round_trips() -> None:
    """A subscription with no storage accounts is a real reading, and it must
    not come back as a row that has lost its bytes."""
    assert decompress(compress({})) == {}


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


def test_coverage_records_what_the_reading_called_and_under_which_contract() -> None:
    """The half ``permissions`` cannot answer.

    A field absent from a stored capture is a setting nobody set, or an
    api-version too old to return it. Only the contract tells them apart, and a
    rule reading the second as the first raises a finding out of CloudGuard's
    own staleness.
    """
    report = CoverageReport()
    report.record(result(AzureEvidence.STORAGE_ACCOUNTS), {"storage_accounts": []})

    entry = report.to_json()["storage_accounts"]
    assert entry["endpoints"] == [
        {"path": STORAGE_ENDPOINT.path, "api_version": STORAGE_ENDPOINT.api_version}
    ]


def test_the_payloads_stay_out_of_the_serialized_coverage() -> None:
    """Coverage travels inside the snapshot, which already holds the data.
    Serializing the payloads there would write every listing twice."""
    report = CoverageReport()
    report.record(result(AzureEvidence.STORAGE_ACCOUNTS), {"storage_accounts": [1, 2, 3]})

    serialized = report.to_json()["storage_accounts"]
    assert "payload" not in serialized
    # Exhaustive on purpose: the guard is that a payload never appears here,
    # and a set comparison catches a new key carrying one in far better than a
    # membership check would.
    assert set(serialized) == {
        # The bare evidence key and the region, stated rather than recoverable
        # by splitting the entry name apart.
        "key",
        "region",
        "category",
        "outcome",
        "detail",
        "item_count",
        "permissions",
        "endpoints",
    }


class StubBlob:
    """The stored row as ``_rebuild_capture`` uses it: a hash and its bytes."""

    def __init__(self, content_hash: str, payload: dict) -> None:
        self.content_hash = content_hash
        self.payload_compressed = compress(payload)

    @property
    def content(self) -> dict:
        return decompress(self.payload_compressed)


class StubSession:
    def __init__(self, blobs: list) -> None:
        self._blobs = blobs

    async def execute(self, _statement: object) -> "StubSession":
        return self

    def scalars(self) -> "StubSession":
        return self

    def all(self) -> list:
        return self._blobs


# --------------------------------------------------- which form a capture is in
async def test_a_capture_with_a_manifest_is_never_read_as_inline_data() -> None:
    """The bug that failed every scan for a release, held shut.

    ``cloud_snapshots.data`` was created ``DEFAULT '{}'::jsonb`` and 0027
    dropped only its NOT NULL, so a capture written as a manifest came back
    carrying an empty object. A read path that chose the inline form on
    "``data`` is not NULL" then rebuilt an estate with nothing in it -- and
    nothing failed until ANALYZE, on a capture that had been stored perfectly.

    So the manifest decides, because it is the thing that is present in one
    form and absent in the other. ``session`` is never reached: a manifest
    naming no readings resolves no blobs.
    """
    payload = {"virtual_machines": [{"id": "/v"}]}
    content_hash = digest(payload)[0]
    row = SimpleNamespace(
        manifest={
            "provider": "azure",
            "tenant_id": "t",
            "payload_hashes": {"virtual_machines": content_hash},
        },
        # What the default supplied, and what used to be taken for a capture.
        data={},
    )
    session = StubSession([StubBlob(content_hash, payload)])

    rebuilt = await _rebuild_capture(session, uuid4(), row)  # type: ignore[arg-type]

    assert rebuilt["provider"] == "azure"
    assert rebuilt["data"] == payload


async def test_a_capture_with_neither_form_is_refused() -> None:
    """Rather than returned as an estate with nothing in it.

    A capture holding no readings at all cannot be replayed, and replaying it
    as empty would resolve findings on the strength of a reading nobody made --
    the same overclaim as a PASS nobody earned.
    """
    row = SimpleNamespace(manifest=None, data=None)

    with pytest.raises(SnapshotUnavailable):
        await _rebuild_capture(None, uuid4(), row)  # type: ignore[arg-type]


async def test_a_capture_written_before_the_manifest_still_reads_inline() -> None:
    """The fallback 0027 kept on purpose: an old capture carries its payloads
    inline and must go on being replayable."""
    row = SimpleNamespace(manifest=None, data={"provider": "azure", "data": {"vms": []}})

    rebuilt = await _rebuild_capture(None, uuid4(), row)  # type: ignore[arg-type]

    assert rebuilt["data"] == {"vms": []}


# ------------------------------------------- one fetch for a tenant's captures
async def test_a_rebuild_given_its_readings_asks_the_database_for_nothing() -> None:
    """What makes a tenant-wide analysis one query rather than fifty.

    Every capture used to fetch its own readings, so an analysis of a
    fifty-subscription tenant opened with fifty round trips against the largest
    table in the schema before a single rule ran. The readings are
    content-addressed and the captures share them, so they are fetched together
    and handed down.
    """
    payload = {"virtual_machines": [{"id": "/v"}]}
    content_hash = digest(payload)[0]
    row = SimpleNamespace(
        manifest={
            "provider": "azure",
            "tenant_id": "t",
            "payload_hashes": {"virtual_machines": content_hash},
        },
        data={},
    )

    class Exploding:
        async def execute(self, _statement: object) -> None:
            raise AssertionError("a rebuild handed its readings must not query")

    rebuilt = await _rebuild_capture(
        Exploding(),  # type: ignore[arg-type]
        uuid4(),
        row,
        {content_hash: payload},
    )

    assert rebuilt["data"] == payload


async def test_a_reading_missing_from_the_batch_is_still_refused() -> None:
    """The interlock does not weaken because the fetch moved. Half a capture
    replays as an estate that has lost whatever the missing half held, which is
    the same overclaim as a PASS nobody earned."""
    row = SimpleNamespace(
        manifest={"payload_hashes": {"virtual_machines": "a" * 64}},
        data={},
    )

    with pytest.raises(SnapshotUnavailable):
        await _rebuild_capture(None, uuid4(), row, {})  # type: ignore[arg-type]


def test_the_batch_asks_for_every_hash_every_capture_names() -> None:
    from app.services.scanner import _manifest_hashes

    captures = [
        SimpleNamespace(manifest={"payload_hashes": {"vms": "a" * 64}}),
        SimpleNamespace(
            manifest={"payload_hashes": {"vms": "a" * 64, "storage": "b" * 64}}
        ),
        # Written before manifests: its readings are inline and none are fetched.
        SimpleNamespace(manifest=None),
    ]

    assert _manifest_hashes(captures) == {"a" * 64, "b" * 64}
