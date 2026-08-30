"""Joining a log line back to the scan that produced it.

A scan runs as several Celery tasks across several workers, so its lines arrive
interleaved with every other tenant's and are joined only by whichever ids each
call site remembered to pass. "Why was this scan slow" is already answerable
from the per-stage durations; this is the other half of the same question --
given a line, which scan, which step, which task.

Deliberately not OpenTelemetry: spans need a collector to send them to, and an
exporter writing into a socket nobody reads is the appearance of observability
rather than the thing.
"""

from collections.abc import Iterator

import pytest
import structlog

from app.core.logging import log_context


@pytest.fixture
def entries() -> Iterator[list[dict]]:
    """What a bound logger emits, with the real configuration put back after.

    structlog is configured process-wide, so a test that reconfigures it and
    walks away decides how every test after it logs -- including the ones that
    assert on nothing and would simply stop being able to emit.
    """
    previous = structlog.get_config()
    captured: list[dict] = []

    def sink(_logger: object, _name: str, event_dict: dict) -> dict:
        captured.append(dict(event_dict))
        raise structlog.DropEvent

    structlog.configure(
        processors=[structlog.contextvars.merge_contextvars, sink],
        cache_logger_on_first_use=False,
    )
    try:
        yield captured
    finally:
        structlog.configure(**previous)


def test_every_line_inside_the_block_carries_the_ids(entries) -> None:
    log = structlog.get_logger("test")

    with log_context(scan_id="scan-1", step_id="step-1", task="run_scan_step"):
        log.info("collection.started")
        log.info("collection.finished")

    assert [e["scan_id"] for e in entries] == ["scan-1", "scan-1"]
    assert entries[0]["step_id"] == "step-1"
    assert entries[1]["task"] == "run_scan_step"


def test_the_ids_do_not_leak_past_the_block(entries) -> None:
    """A worker process handles other tenants' scans next. Context that
    outlived its block would attribute their lines to this scan."""
    log = structlog.get_logger("test")

    with log_context(scan_id="scan-1"):
        log.info("inside")
    log.info("outside")

    assert "scan_id" in entries[0]
    assert "scan_id" not in entries[1]


def test_absent_ids_are_left_out_rather_than_bound_as_none(entries) -> None:
    """A directory step has no subscription. ``cloud_account_id=None`` reads as
    a step whose subscription is unknown, rather than as one that is not about
    a subscription at all."""
    log = structlog.get_logger("test")

    with log_context(scan_id="scan-1", cloud_account_id=None):
        log.info("directory.collected")

    assert entries[0]["scan_id"] == "scan-1"
    assert "cloud_account_id" not in entries[0]


def test_an_inner_block_adds_to_the_outer_one(entries) -> None:
    """A step's context nests inside its task's rather than replacing it."""
    log = structlog.get_logger("test")

    with log_context(scan_id="scan-1"):
        with log_context(step_id="step-1"):
            log.info("inner")
        log.info("outer")

    assert entries[0] == {"scan_id": "scan-1", "step_id": "step-1", "event": "inner"}
    assert "step_id" not in entries[1]
