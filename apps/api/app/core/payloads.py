"""How a collected payload becomes bytes, and how it comes back.

A payload is a provider listing: the raw JSON one reading produced. Three
questions about it used to have two different answers in two different files --
what hash it is stored under, what size that hash was taken over, and what is
actually written to the row -- so they live here together instead.

**The stored bytes are the hashed bytes, compressed.** ``canonical`` is the one
serialization the hash is ever taken over, and it is that exact byte string
that gets compressed and written. So a stored payload can always be checked
against the hash it is filed under: decompress, hash, compare. A version that
compressed ``json.dumps(payload)`` afresh would round-trip to an equal dict and
a different byte string, and the check would be a coin toss between a real
corruption and a whitespace difference.

**zlib rather than zstd or brotli.** Azure listings are deeply repetitive JSON
-- the same resource-group prefix on every id, the same twenty property names
on every row -- and zlib gets roughly a tenth of the size on them. zstd would
get perhaps a fifth off that again, at the price of a native wheel in the API
image, the worker image, and CI, for bytes that are already an order of
magnitude down. The compression happens on the scan's hot path, so the level is
the balanced one rather than the maximum: level 9 spends noticeably longer for
a low single-digit percentage on this kind of input.
"""

import hashlib
import json
import zlib

# Balanced rather than maximal: see the module docstring.
COMPRESSION_LEVEL = 6


def canonical(payload: dict) -> bytes:
    """The single serialization a payload is hashed and stored as.

    ``sort_keys`` and the compact separators are what make the hash a *content*
    hash rather than a hash of one particular serialization. Two scans that read
    the same environment must produce the same digest, or the deduplication is
    decorative -- and JSON dict ordering is not something a provider promises.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def digest(payload: dict) -> tuple[str, int]:
    """A payload's content hash, and the size of the bytes it was taken over.

    The size is the uncompressed one on purpose. It is what a customer means by
    "how much did this scan read", and it stays comparable across payloads
    stored before compression existed and after it.
    """
    encoded = canonical(payload)
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


def compress(payload: dict) -> bytes:
    """The bytes to store for this payload."""
    return zlib.compress(canonical(payload), COMPRESSION_LEVEL)


def decompress(stored: bytes) -> dict:
    """The payload back out of its stored bytes.

    zlib carries its own checksum, so a truncated or corrupted value raises
    here rather than surfacing as JSON that half-parses.
    """
    decoded: dict = json.loads(zlib.decompress(stored))
    return decoded
