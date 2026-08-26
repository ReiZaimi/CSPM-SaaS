"""JWT verification.

CloudGuard does not implement authentication -- Supabase Auth does. This module
only *verifies* the token Supabase issued and extracts the user id. Nothing here
grants access to anything: authorization is membership resolution (app layer)
plus RLS (database layer).
"""

from dataclasses import dataclass
from uuid import UUID

import jwt

from app.core.config import settings
from app.core.errors import NotAuthenticated

ALGORITHM = "HS256"


@dataclass(frozen=True)
class AuthenticatedUser:
    id: UUID
    email: str | None = None


def decode_token(token: str) -> AuthenticatedUser:
    """Verify a Supabase Auth JWT and return the caller's identity.

    Signature, expiry and audience are all checked. A token that fails any of
    them is simply not authenticated -- we never fall through to a "best guess"
    user.
    """
    if not settings.supabase_jwt_secret:
        raise NotAuthenticated("Server has no JWT secret configured")

    try:
        claims = jwt.decode(
            token,
            settings.supabase_jwt_secret,
            algorithms=[ALGORITHM],
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
