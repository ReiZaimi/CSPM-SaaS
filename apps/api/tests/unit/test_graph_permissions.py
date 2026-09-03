"""Knowing which directory permissions a tenant actually granted.

Admin consent resolves ``/.default`` to whatever the app registration declares
at the moment it is clicked. A registration missing permissions therefore
produces a consent screen that looks entirely successful, a connection that
verifies, and a first scan that loses the identity category to "Insufficient
privileges to complete the operation" -- a sentence that names nothing.

The token already knows. A client-credentials token lists its granted
application permissions in the ``roles`` claim, so the answer is in hand before
any call is made.
"""

import jwt

from app.connectors.azure.auth import (
    GRAPH_APP_ROLES,
    GRAPH_PERMISSION_USE,
    GRAPH_RESOURCE_APP_ID,
    REQUIRED_GRAPH_PERMISSIONS,
    RESERVED_GRAPH_PERMISSIONS,
    app_registration_manifest,
    granted_permissions,
    missing_permissions,
)


def token_granting(*permissions: str) -> str:
    return jwt.encode({"roles": list(permissions)}, "irrelevant", algorithm="HS256")


# ------------------------------------------------------------- reading a token
def test_a_fully_consented_token_is_missing_nothing() -> None:
    token = token_granting(*REQUIRED_GRAPH_PERMISSIONS)
    assert granted_permissions(token) == frozenset(REQUIRED_GRAPH_PERMISSIONS)
    assert missing_permissions(token) == ()


def test_a_partial_grant_names_exactly_what_is_absent() -> None:
    """The reported failure: /users and /directoryRoles both refused."""
    token = token_granting("Policy.Read.All", "Application.Read.All")
    absent = missing_permissions(token)

    assert "Directory.Read.All" in absent
    assert "User.Read.All" in absent
    assert "RoleManagement.Read.Directory" in absent
    assert "Policy.Read.All" not in absent
    assert len(absent) == len(REQUIRED_GRAPH_PERMISSIONS) - 2


def test_missing_permissions_keeps_the_declared_order() -> None:
    """Read aloud in an error message, so it should not be set-ordered."""
    absent = missing_permissions(token_granting("Policy.Read.All"))
    assert list(absent) == [p for p in REQUIRED_GRAPH_PERMISSIONS if p != "Policy.Read.All"]


def test_a_token_with_no_roles_claim_reports_everything_missing() -> None:
    """Consent that granted nothing at all is the case actually seen, and the
    one that used to report no gaps -- an empty grant and an unreadable token
    were the same value, so the worst outcome read as the healthiest."""
    assert granted_permissions(token_granting()) == frozenset()
    assert missing_permissions(token_granting()) == tuple(REQUIRED_GRAPH_PERMISSIONS)
    assert missing_permissions(
        jwt.encode({"roles": []}, "x", algorithm="HS256")
    ) == tuple(REQUIRED_GRAPH_PERMISSIONS)


def test_an_unreadable_token_claims_no_knowledge() -> None:
    """An unreadable token is not evidence of a missing grant. Reporting nine
    phantom gaps would send an administrator to fix something that works."""
    assert granted_permissions("not-a-jwt") is None
    assert missing_permissions("not-a-jwt") == ()


def test_the_signature_is_never_trusted() -> None:
    """Read for diagnosis, never for authorization -- Microsoft stays the
    enforcer. A token signed with any key at all still parses here, which is
    exactly why nothing may be authorized on the strength of it."""
    forged = jwt.encode({"roles": ["Directory.Read.All"]}, "whatever", algorithm="HS256")
    assert "Directory.Read.All" in granted_permissions(forged)


# ------------------------------------------------------ the registration itself
def test_every_required_permission_has_a_role_id() -> None:
    """Entra addresses permissions by id, never by name, so a permission
    without one cannot be deployed."""
    for permission in REQUIRED_GRAPH_PERMISSIONS:
        assert permission in GRAPH_APP_ROLES, f"{permission} has no app role id"


def test_role_ids_are_guids_and_distinct() -> None:
    """A wrong id here is indistinguishable from a right one by inspection and
    fails in front of a customer's Global Administrator."""
    import uuid

    for name, role_id in GRAPH_APP_ROLES.items():
        assert uuid.UUID(role_id), f"{name} has a malformed id"
    assert len(set(GRAPH_APP_ROLES.values())) == len(GRAPH_APP_ROLES)


def test_the_manifest_declares_application_permissions_on_graph() -> None:
    manifest = app_registration_manifest()

    assert len(manifest) == 1
    assert manifest[0]["resourceAppId"] == GRAPH_RESOURCE_APP_ID

    access = manifest[0]["resourceAccess"]
    assert len(access) == len(REQUIRED_GRAPH_PERMISSIONS)
    # "Role" is an application permission. "Scope" is delegated, which a
    # background scanner with no signed-in user can never exercise.
    assert {entry["type"] for entry in access} == {"Role"}
    assert {entry["id"] for entry in access} == {
        GRAPH_APP_ROLES[p] for p in REQUIRED_GRAPH_PERMISSIONS
    }


def test_the_manifest_covers_the_permissions_the_collector_needs() -> None:
    """The two lists are written apart and must not drift: a permission the
    connector probes for but the registration never requests is one no customer
    can ever grant."""
    from app.connectors.azure.connector import GRAPH_PROBES

    declared = set(REQUIRED_GRAPH_PERMISSIONS)
    for _probe, _subject, permission in GRAPH_PROBES:
        # Probes name alternatives ("A or B"); at least one must be declared.
        options = {p.strip() for p in permission.split(" or ")}
        assert options & declared, f"nothing in the registration grants {permission}"


# ------------------------------------- a permission nothing uses, on the screen
def test_every_requested_permission_is_used_or_reserved() -> None:
    """The Graph half of ``ROLE_ONLY_ACTIONS``.

    ARM has asserted for a long time that the scanner role requests no action
    no collector reaches. Graph asserted nothing, and it cost: three
    permissions sat on the consent screen with nothing calling them, so what
    CloudGuard could already read was read off the collector rather than off
    the grant -- and application credentials and dormant accounts were both
    filed as needing a second admin consent that every connected tenant had
    already given (``DECISIONS.md`` section 63).

    Reserved is a permitted answer. Silence is not.
    """
    unexplained = [
        permission
        for permission in REQUIRED_GRAPH_PERMISSIONS
        if not GRAPH_PERMISSION_USE.get(permission)
        and permission not in RESERVED_GRAPH_PERMISSIONS
    ]
    assert unexplained == [], (
        "requested on a customer's consent screen with nothing calling it and "
        f"no reason recorded: {unexplained}"
    )


def test_a_reserved_permission_says_why_it_is_there() -> None:
    for permission, reason in RESERVED_GRAPH_PERMISSIONS.items():
        assert permission in REQUIRED_GRAPH_PERMISSIONS
        assert reason.strip(), f"{permission} is reserved for no stated reason"
        assert not GRAPH_PERMISSION_USE.get(permission), (
            f"{permission} is both used and reserved"
        )


def test_every_declared_use_names_a_call_that_exists() -> None:
    """The declaration is only worth having if it cannot drift.

    A method renamed out from under this map would leave a permission looking
    used while nothing calls it -- the exact state this map exists to make
    impossible.
    """
    from app.connectors.azure.client import GraphClient

    for permission, methods in GRAPH_PERMISSION_USE.items():
        assert permission in REQUIRED_GRAPH_PERMISSIONS, (
            f"{permission} is declared as used and never requested"
        )
        for method in methods:
            assert callable(getattr(GraphClient, method, None)), (
                f"{permission} names {method}, which GraphClient does not have"
            )
