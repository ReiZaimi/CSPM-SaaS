"""The production configuration guard.

This code path runs exactly once per deploy and never during development,
which is precisely why it needs tests: a mistake here is invisible until the
day it matters, and its whole job is to catch mistakes that are otherwise
invisible.
"""

import pytest

from app.core.config import DEV_CONSENT_SECRET, DEV_JWT_SECRET, Settings

PRODUCTION_READY = {
    "app_env": "production",
    "supabase_url": "https://abc.supabase.co",
    "supabase_jwt_secret": "a-real-secret-from-the-supabase-dashboard",
    "azure_consent_state_secret": "a-real-random-32-character-string-here",
    "cors_origins": ["https://cloudguard.example.com"],
}


def settings_with(**overrides: object) -> Settings:
    # _env_file=None so a developer's own .env cannot leak into the assertions.
    return Settings(_env_file=None, **{**PRODUCTION_READY, **overrides})  # type: ignore[arg-type]


class TestProductionGuard:
    def test_a_correctly_configured_deployment_has_no_problems(self) -> None:
        assert settings_with().production_config_problems() == []

    def test_default_jwt_secret_is_rejected(self) -> None:
        """A known signing secret means anyone can mint a token for any user."""
        problems = settings_with(supabase_jwt_secret=DEV_JWT_SECRET).production_config_problems()
        assert any("SUPABASE_JWT_SECRET" in p for p in problems)

    def test_empty_jwt_secret_is_rejected(self) -> None:
        problems = settings_with(supabase_jwt_secret="").production_config_problems()
        assert any("SUPABASE_JWT_SECRET" in p for p in problems)

    def test_default_consent_secret_is_rejected(self) -> None:
        """It signs the Entra consent round-trip -- a known value lets an
        attacker bind their tenant to someone else's cloud account."""
        problems = settings_with(
            azure_consent_state_secret=DEV_CONSENT_SECRET
        ).production_config_problems()
        assert any("AZURE_CONSENT_STATE_SECRET" in p for p in problems)

    def test_localhost_cors_origin_is_rejected(self) -> None:
        problems = settings_with(
            cors_origins=["https://real.example.com", "http://localhost:5173"]
        ).production_config_problems()
        assert any("CORS_ORIGINS" in p for p in problems)

    def test_missing_supabase_url_is_rejected(self) -> None:
        """Without it, the dev sign-in route stays registered in production --
        and that route mints a token for any email handed to it."""
        problems = settings_with(supabase_url="").production_config_problems()
        assert any("SUPABASE_URL" in p for p in problems)

    def test_every_problem_explains_the_consequence_not_just_the_variable(self) -> None:
        """A deploy-time error is read by someone under time pressure. Naming
        the variable without saying why it matters invites working around it."""
        problems = settings_with(
            supabase_jwt_secret=DEV_JWT_SECRET,
            azure_consent_state_secret=DEV_CONSENT_SECRET,
            supabase_url="",
            cors_origins=["http://localhost:5173"],
        ).production_config_problems()

        assert len(problems) == 4
        for problem in problems:
            assert len(problem) > 80, f"too terse to act on: {problem}"

    @pytest.mark.parametrize("env", ["development", "test", "staging"])
    def test_the_guard_only_applies_to_production(self, env: str) -> None:
        """Local development runs on these defaults by design; the guard must
        not make `docker compose up` fail."""
        insecure = settings_with(
            app_env=env,
            supabase_jwt_secret=DEV_JWT_SECRET,
            supabase_url="",
            cors_origins=["http://localhost:5173"],
        )
        assert insecure.is_production is False
        # main.py only consults the guard when is_production is true.
