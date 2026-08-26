"""JWT verification.

CloudGuard does not implement authentication -- Supabase Auth does. This module
only *verifies* the token Supabase issued and extracts the user id. Nothing here
grants access to anything: authorization is membership resolution (app layer)
plus RLS (database layer).

Supabase signs tokens two different ways depending on the project's age and
settings:

* **ES256 / RS256** -- asymmetric, and the current default. The public keys are
  published at the project's JWKS endpoint; there is no shared secret to hold,
  and keys can rotate without redeploying this service.
* **HS256** -- the legacy shared secret (SUPABASE_JWT_SECRET).

Both are supported, chosen per token from the header's ``alg``. Critically the
algorithm is never treated as a *permission*: the token must verify under a key
appropriate to the algorithm it declares, and anything else -- including
``none`` -- is refused outright rather than falling through to a weaker check.
"""

from dataclasses import dataclass
from functools import lru_cache
from uuid import UUID

import jwt
from jwt import PyJWKClient

from app.core.config import settings
from app.core.errors import NotAuthenticated

# What Supabase issues. "none" and the wider symmetric family are deliberately
# absent: accepting an attacker-chosen algorithm is the classic JWT confusion
# attack.
ASYMMETRIC_ALGORITHMS = ("ES256", "RS256")
SYMMETRIC_ALGORITHMS = ("HS256",)
SUPPORTED_ALGORITHMS = ASYMMETRIC_ALGORITHMS + SYMMETRIC_ALGORITHMS


@dataclass(frozen=True)
class AuthenticatedUser:
    id: UUID
    email: str | None = None


@lru_cache
def _jwk_client() -> PyJWKClient:
    """Client for the project's published signing keys.

    Cached because it maintains its own key cache -- rebuilding it per request
    would fetch the JWKS document on every call.
    """
    base = settings.supabase_url.rstrip("/")
    return PyJWKClient(f"{base}/auth/v1/.well-known/jwks.json")


def _signing_key(token: str, algorithm: str) -> str:
    if algorithm in ASYMMETRIC_ALGORITHMS:
        if not settings.supabase_url:
            raise NotAuthenticated("Server has no Supabase project configured")
        try:
            return _jwk_client().get_signing_key_from_jwt(token).key
        except Exception as exc:
            raise NotAuthenticated(
                "Could not verify the token's signing key against the Supabase project"
            ) from exc

    if not settings.supabase_jwt_secret:
        raise NotAuthenticated(
            "Token is signed with a shared secret but SUPABASE_JWT_SECRET is not set"
        )
    return settings.supabase_jwt_secret


def decode_token(token: str) -> AuthenticatedUser:
    """Verify a Supabase Auth JWT and return the caller's identity.

    Signature, expiry and audience are all checked. A token failing any of them
    is simply not authenticated -- we never fall through to a "best guess" user.
    """
    try:
        algorithm = jwt.get_unverified_header(token).get("alg", "")
    except jwt.InvalidTokenError as exc:
        raise NotAuthenticated("Malformed authentication token") from exc

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise NotAuthenticated(
            f"Unsupported token signing algorithm: {algorithm or 'none'}"
        )

    key = _signing_key(token, algorithm)

    try:
        claims = jwt.decode(
            token,
            key,
            # Pinned to the one algorithm the header declared and whose key was
            # just resolved for it, so a token cannot be verified under another.
            algorithms=[algorithm],
            audience=settings.jwt_audience,
            options={"require": ["sub", "exp"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise NotAuthenticated("Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise NotAuthenticated("Invalid authentication token") from exc

    try:
        user_id = UUID(str(claims["sub"]))
    except (KeyError, ValueError) as exc:
        raise NotAuthenticated("Token subject is not a valid user id") from exc

    return AuthenticatedUser(id=user_id, email=claims.get("email"))
