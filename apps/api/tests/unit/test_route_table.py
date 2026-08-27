"""Route-table hygiene.

FastAPI matches routes in declaration order, so a literal path declared after a
parameterised one that could also match it is simply unreachable. That is a
quiet failure: the request lands on the wrong handler and fails for the wrong
reason.

It bit the artifact endpoint, which is unauthenticated by design because a
customer's Cloud Shell fetches it. Declared after ``/{connection_id}`` it was
answered by that route instead, and the symptom was a 401 -- from a shell
session that never had a CloudGuard session to present, on a URL where a 401
makes no sense. Nothing in the message pointed at routing.

This checks every router rather than the one that had the bug.
"""

from app.core.config import CONSENT_CALLBACK_PATH
from app.main import app


def declared_routes() -> list[tuple[str, set[str]]]:
    return [
        (route.path, set(route.methods))
        for route in app.routes
        if getattr(route, "methods", None)
    ]


def shadows(earlier: str, later: str) -> bool:
    """True when a request for ``later`` would be answered by ``earlier``."""
    earlier_segments = earlier.strip("/").split("/")
    later_segments = later.strip("/").split("/")
    if len(earlier_segments) != len(later_segments):
        return False

    pairs = list(zip(earlier_segments, later_segments, strict=True))
    matches_every_segment = all(
        early.startswith("{") or early == late for early, late in pairs
    )
    # A path only *shadows* another if it is strictly more general somewhere;
    # two identical literal paths are a different (and louder) problem.
    is_more_general = any(
        early.startswith("{") and not late.startswith("{") for early, late in pairs
    )
    return matches_every_segment and is_more_general


def test_no_route_is_unreachable() -> None:
    routes = declared_routes()
    unreachable = [
        f"{sorted(methods)} {path} is shadowed by {earlier_path} declared above it"
        for index, (path, methods) in enumerate(routes)
        for earlier_path, earlier_methods in routes[:index]
        if methods & earlier_methods and shadows(earlier_path, path)
    ]
    assert unreachable == []


def test_shadows_detects_the_bug_it_was_written_for() -> None:
    """Guard the guard: a check that never fires proves nothing."""
    assert shadows("/cloud-connections/{connection_id}", "/cloud-connections/artifact")
    assert not shadows("/cloud-connections/artifact", "/cloud-connections/{id}")
    assert not shadows("/cloud-connections/{id}", "/cloud-connections/{id}/validate")
    assert not shadows("/a/{id}", "/b/literal")


def test_the_consent_callback_path_is_actually_served() -> None:
    """`CONSENT_CALLBACK_PATH` is what AZURE_REDIRECT_URI is validated against,
    and what customers register with Entra. If the router moves and that
    constant does not, the check passes a URI Entra will send to a 404 -- and
    the failure lands after consent has already been granted."""
    assert any(path == CONSENT_CALLBACK_PATH for path, _ in declared_routes())
