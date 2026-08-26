"""Token verification.

The only thing standing between a request and someone else's tenant, so the
failure modes matter more than the happy path: an unexpected algorithm, a
forged signature, a token that has expired, and the classic JWT confusion
attack where the attacker picks the algorithm.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app.core.config import Settings
from app.core.errors import NotAuthenticated

SECRET = "a-shared-hs256-secret"


@pytest.fixture(autouse=True)
def _hs256_project(monkeypatch: pytest.MonkeyPatch):
    """A legacy project that signs with a shared secret."""
    import app.core.security as security

    monkeypatch.setattr(
        security,
        "settings",
        Settings(
            app_env="test",
            supabase_url="https://abc.supabase.co",
            supabase_jwt_secret=SECRET,
        ),
    )
    security._jwk_client.cache_clear()
    return security


def make_token(
    *, secret: str = SECRET, alg: str = "HS256", key=None, **overrides
) -> str:
    now = datetime.now(UTC)
    claims = {
        "sub": str(uuid4()),
        "email": "user@example.com",
        "aud": "authenticated",
        "iat": now,
        "exp": now + timedelta(hours=1),
        **overrides,
    }
    return jwt.encode(claims, key if key is not None else secret, algorithm=alg)


class TestAcceptsValidTokens:
    def test_a_correctly_signed_token_identifies_the_user(self, _hs256_project) -> None:
        user_id = uuid4()
        token = make_token(sub=str(user_id))
        result = _hs256_project.decode_token(token)
        assert result.id == user_id
        assert result.email == "user@example.com"


class TestRejectsBadTokens:
    def test_a_forged_signature_is_rejected(self, _hs256_project) -> None:
        token = make_token(secret="not-the-real-secret")
        with pytest.raises(NotAuthenticated):
            _hs256_project.decode_token(token)

    def test_an_expired_token_is_rejected(self, _hs256_project) -> None:
        past = datetime.now(UTC) - timedelta(hours=2)
        token = make_token(exp=past, iat=past - timedelta(hours=1))
        with pytest.raises(NotAuthenticated, match="expired"):
            _hs256_project.decode_token(token)

    def test_a_token_for_another_audience_is_rejected(self, _hs256_project) -> None:
        token = make_token(aud="some-other-service")
        with pytest.raises(NotAuthenticated):
            _hs256_project.decode_token(token)

    def test_a_non_uuid_subject_is_rejected(self, _hs256_project) -> None:
        """The subject becomes the identity RLS resolves against."""
        token = make_token(sub="not-a-uuid")
        with pytest.raises(NotAuthenticated, match="not a valid user id"):
            _hs256_project.decode_token(token)

    def test_garbage_is_rejected(self, _hs256_project) -> None:
        with pytest.raises(NotAuthenticated):
            _hs256_project.decode_token("not-a-jwt-at-all")


class TestAlgorithmConfusion:
    def test_an_unsigned_token_is_rejected(self, _hs256_project) -> None:
        """alg=none is the oldest JWT attack there is."""
        token = jwt.encode(
            {"sub": str(uuid4()), "aud": "authenticated", "exp": 9999999999},
            key="",
            algorithm="none",
        )
        with pytest.raises(NotAuthenticated, match="Unsupported token signing algorithm"):
            _hs256_project.decode_token(token)

    def test_an_unexpected_algorithm_is_rejected(self, _hs256_project) -> None:
        token = make_token(secret=SECRET, alg="HS512")
        with pytest.raises(NotAuthenticated, match="Unsupported token signing algorithm"):
            _hs256_project.decode_token(token)

    def test_an_asymmetric_token_is_not_verified_with_the_shared_secret(
        self, _hs256_project
    ) -> None:
        """The confusion attack in its dangerous form: an ES256 header must send
        us to the JWKS endpoint, never to the HS256 secret. Here the project URL
        is unreachable in tests, so the correct outcome is a clean refusal."""
        key = ec.generate_private_key(ec.SECP256R1())
        token = make_token(alg="ES256", key=key)
        with pytest.raises(NotAuthenticated):
            _hs256_project.decode_token(token)


class TestMissingConfiguration:
    def test_hs256_without_a_secret_says_so_precisely(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An asymmetric project has no shared secret; if a legacy token turns
        up anyway, the message should name the variable rather than read as a
        generic auth failure."""
        import app.core.security as security

        monkeypatch.setattr(
            security,
            "settings",
            Settings(
                app_env="test",
                supabase_url="https://abc.supabase.co",
                supabase_jwt_secret="",
            ),
        )
        with pytest.raises(NotAuthenticated, match="SUPABASE_JWT_SECRET"):
            security.decode_token(make_token())
