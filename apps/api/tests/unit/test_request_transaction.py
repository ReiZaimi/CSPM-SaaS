"""Nothing in the request path may commit the transaction it was handed.

``rls_session`` wraps a whole request in ``session.begin()`` and declares who is
asking with ``SET LOCAL ROLE authenticated`` and ``request.jwt.claims``. Both
are *transaction*-scoped, which is exactly what stops them leaking to the next
checkout of a pooled connection -- and it also means a commit inside a request
tears down the settings every RLS policy reads.

``set_change_events`` committed directly. Turning change detection off worked,
because nothing ran afterwards. Turning it *on* did not: the route goes on to
build the Event Grid commands, which reads the connection's subscriptions, and
that read ran as the bare role with no claims. The customer saw a request that
failed for no reason they could act on, on the one screen whose job is saying
what is wrong.

Asserted over the module rather than over the one function that had the bug.
The next service written here will be written by someone who has not read this
file, and the failure it reintroduces is silent in the direction that matters.
"""

import ast
from pathlib import Path

import pytest

SERVICES = Path(__file__).resolve().parents[2] / "app" / "services"

# Code that opens its own session and therefore owns the transaction it
# commits. Listed per function rather than per module, because a module is not
# the unit that has a session contract: ``scans.py`` holds both the reaper,
# which a worker calls under ``service_session``, and the endpoints a request
# reaches under ``rls_session``, and exempting the file would exempt those too.
#
# Each entry is here because it is unreachable from a request, not because a
# commit in it was inconvenient to remove.
WORKER_OWNED = {
    # The pipeline and its orchestrator run under ``scan_session``, which
    # deliberately does not own its transaction: a scan commits per phase so
    # collection is durable before evaluation starts, and re-declares its claim
    # on every transaction through an ``after_begin`` listener.
    "scanner.py": None,
    "orchestrator.py": None,
    # Opens its own ``service_session``; called from the app's lifespan.
    "rule_sync.py": {"sync_rules_to_database"},
    # The abandoned-scan reaper, called by the Celery beat task under
    # ``service_session``. It looks across every organization, which is exactly
    # what a per-user session cannot do.
    "scans.py": {"reap_abandoned_scans"},
}


def committing_functions(path: Path) -> list[str]:
    """Every function in this module that calls ``session.commit()`` directly."""
    tree = ast.parse(path.read_text())
    found: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
            continue
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            func = call.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "commit"
                and isinstance(func.value, ast.Name)
                and func.value.id == "session"
            ):
                found.append(node.name)
                break
    return found


@pytest.mark.parametrize("module", sorted(p.name for p in SERVICES.glob("*.py")))
def test_a_service_does_not_commit_a_transaction_it_may_not_own(module: str) -> None:
    """``commit_unless_externally_managed`` is the only way to commit here.

    It is a no-op under ``rls_session`` and a real commit under
    ``service_session``, so the same service code is correct from both -- which
    is the whole reason it exists.
    """
    if module in WORKER_OWNED and WORKER_OWNED[module] is None:
        pytest.skip("runs only under scan_session, which owns no transaction")

    allowed = WORKER_OWNED.get(module) or set()
    offenders = [
        name for name in committing_functions(SERVICES / module) if name not in allowed
    ]

    assert offenders == [], (
        f"{module} commits directly in {offenders}; use "
        "commit_unless_externally_managed, or the JWT claims and role that RLS "
        "depends on are torn down mid-request"
    )
