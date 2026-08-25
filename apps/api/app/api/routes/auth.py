"""Development-only auth helper.

Production authentication is Supabase Auth: the browser signs in against
Supabase directly and sends the resulting JWT to this API, which verifies it
(``app.core.security``). CloudGuard never sees a password.

This router exists so the full product loop can be exercised before a Supabase
project is provisioned. It refuses to operate in production, and it is not
registered at all when Supabase is configured.
"""

import uuid

from fastapi import APIRouter
from pydantic import BaseModel, EmailStr

from app.core.config import settings
from app.core.errors import NotFound, envelope
from app.core.security import issue_local_token

router = APIRouter(prefix="/auth", tags=["auth"])

# Stable per-email user ids, so a "sign in" twice is the same person. Mirrors
# what Supabase would give us without needing a users table of our own.
_DEV_NAMESPACE = uuid.UUID("00000000-0000-0000-0000-0000000c1a11")


class DevSignIn(BaseModel):
    email: EmailStr


def dev_user_id(email: str) -> uuid.UUID:
    return uuid.uuid5(_DEV_NAMESPACE, email.strip().lower())


@router.post("/dev-token")
async def dev_token(payload: DevSignIn) -> dict:
    if settings.is_production:
        raise NotFound()
    user_id = dev_user_id(payload.email)
    return envelope(
        {
            "access_token": issue_local_token(user_id, payload.email),
            "token_type": "bearer",
            "user": {"id": str(user_id), "email": payload.email},
        }
    )
