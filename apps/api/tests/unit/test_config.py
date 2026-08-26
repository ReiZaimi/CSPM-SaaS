"""The configuration guard.

This runs once per deploy and never anywhere else, which is exactly why it
needs tests: a mistake here is invisible until the day it matters, and its
whole job is to catch mistakes that are otherwise invisible.

Each test constructs Settings directly with explicit values. The env is cleared
first so a variable set in CI (which sets DATABASE_URL and friends for the
integration suite) cannot mask a missing-value assertion.
"""

import pytest

from app.core.config import ConfigurationError, Settings

ENV_VARS = [
    "APP_ENV", "APP_URL", "API_URL", "LOG_LEVEL",
    "SUPABASE_URL", "SUPABASE_PUBLISHABLE_KEY", "SUPABASE_SECRET_KEY",
    "SUPABASE_JWT_SECRET", "JWT_AUDIENCE",
    "DATABASE_URL", "DATABASE_OWNER_URL", "DB_ECHO", "REDIS_URL",
    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
    "AZURE_REDIRECT_URI", "AZURE_CONSENT_STATE_SECRET",
    "SENTRY_DSN", "CORS_ORIGINS",
]

DEPLOYABLE = {
    "app_env": "production",
    "app_url": "https://cloudguard.example.com",
    "api_url": "https://api.cloudguard.example.com",
    "supabase_url": "https://abc.supabase.co",
    "supabase_publishable_key": "an-anon-key",
    "supabase_jwt_secret": "a-real-secret-from-the-supabase-dashboard",
    "azure_consent_state_secret": "a-real-random-32-character-string-here",
    "database_url": "postgresql+asyncpg://cloudguard_app:pw@db.abc.supabase.co:5432/postgres",
    "database_owner_url": "postgresql+asyncpg://postgres:pw@db.abc.supabase.co:5432/postgres",
    "redis_url": "redis://default:pw@redis.railway.internal:6379",
    "cors_origins": ["https://cloudguard.example.com"],
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def settings_with(**overrides: object) -> Settings:
    return Settings(**{**DEPLOYABLE, **overrides})  # type: ignore[arg-type]


class TestDeployableEnvironment:
    def test_a_complete_environment_has_no_problems(self) -> None:
        assert settings_with().config_problems() == []

    def test_a_complete_environment_starts(self) -> None:
        settings_with().raise_if_misconfigured()  # must not raise


class TestRequiredValues:
    @pytest.mark.parametrize(
        ("field", "expected"),
        [
            ("database_url", "DATABASE_URL"),
            ("database_owner_url", "DATABASE_OWNER_URL"),
            ("redis_url", "REDIS_URL"),
            ("supabase_url", "SUPABASE_URL"),
            ("supabase_publishable_key", "SUPABASE_PUBLISHABLE_KEY"),
            ("azure_consent_state_secret", "AZURE_CONSENT_STATE_SECRET"),
            ("app_url", "APP_URL"),
        ],
    )
    def test_each_required_value_is_reported_by_name(
        self, field: str, expected: str
    ) -> None:
        problems = settings_with(**{field: ""}).config_problems()
        assert any(expected in p for p in problems), f"{expected} not reported"

    def test_missing_cors_origins_is_reported(self) -> None:
        problems = settings_with(cors_origins=[]).config_problems()
        assert any("CORS_ORIGINS" in p for p in problems)

    def test_an_empty_environment_reports_everything_at_once(self) -> None:
        """Discovering every missing variable one redeploy at a time is its own
        kind of cruelty."""
        problems = Settings(app_env="production").config_problems()
        assert len(problems) >= 8

    def test_jwt_secret_is_not_required(self) -> None:
        """Supabase signs with asymmetric keys by default; those projects have
        no shared secret, and the public keys come from JWKS instead."""
        assert settings_with(supabase_jwt_secret="").config_problems() == []


class TestNoLocalhostLeaks:
    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("app_url", "http://localhost:5173"),
            ("api_url", "http://localhost:8000"),
            ("database_url", "postgresql+asyncpg://cloudguard_app:pw@localhost:5432/cloudguard"),
            ("redis_url", "redis://localhost:6379/0"),
        ],
    )
    def test_localhost_anywhere_is_a_problem(self, field: str, value: str) -> None:
        """There is no local environment to point at -- a localhost value means
        a default leaked into a deployment."""
        problems = settings_with(**{field: value}).config_problems()
        assert any("localhost" in p for p in problems)

    def test_loopback_ip_is_caught_too(self) -> None:
        problems = settings_with(api_url="http://127.0.0.1:8000").config_problems()
        assert any("localhost" in p for p in problems)

    def test_localhost_cors_origin_is_a_problem(self) -> None:
        problems = settings_with(
            cors_origins=["https://real.example.com", "http://localhost:5173"]
        ).config_problems()
        assert any("CORS_ORIGINS" in p for p in problems)


class TestAzureIsOptionalUntilConfigured:
    def test_no_azure_identity_is_not_a_problem(self) -> None:
        """Everything up to the Connections screen works without it."""
        assert settings_with().azure_configured is False
        assert settings_with().config_problems() == []

    def test_redirect_uri_required_once_an_identity_exists(self) -> None:
        problems = settings_with(
            azure_client_id="an-id", azure_client_secret="a-secret"
        ).config_problems()
        assert any("AZURE_REDIRECT_URI" in p for p in problems)

    def test_no_problem_when_the_redirect_uri_is_supplied(self) -> None:
        problems = settings_with(
            azure_client_id="an-id",
            azure_client_secret="a-secret",
            azure_redirect_uri="https://api.example.com/api/v1/cloud-accounts/azure/consent/callback",
        ).config_problems()
        assert problems == []


class TestStartupBehaviour:
    def test_an_incomplete_environment_refuses_to_start(self) -> None:
        with pytest.raises(ConfigurationError) as exc:
            settings_with(database_url="").raise_if_misconfigured()
        assert "DATABASE_URL" in str(exc.value)

    def test_the_error_lists_every_problem_not_just_the_first(self) -> None:
        with pytest.raises(ConfigurationError) as exc:
            Settings(app_env="production").raise_if_misconfigured()
        assert str(exc.value).count("\n  - ") >= 8

    def test_test_environment_is_exempt(self) -> None:
        """CI runs against a throwaway database with no Supabase project."""
        Settings(app_env="test").raise_if_misconfigured()  # must not raise

    def test_staging_is_not_exempt(self) -> None:
        """Staging is a real deployment reachable from the internet."""
        with pytest.raises(ConfigurationError):
            Settings(app_env="staging").raise_if_misconfigured()

    def test_the_default_environment_is_production(self) -> None:
        """Fail closed: a forgotten APP_ENV must not relax the checks."""
        assert Settings().app_env == "production"

    def test_every_problem_explains_the_consequence(self) -> None:
        """A deploy-time error is read by someone under time pressure. Naming
        the variable without saying why invites working around it."""
        for problem in Settings(app_env="production").config_problems():
            assert len(problem) > 60, f"too terse to act on: {problem}"


class TestEnvironmentParsing:
    """Values as the platform actually supplies them: strings, via os.environ.

    The rest of this file constructs Settings with init kwargs, which bypasses
    pydantic-settings' EnvSettingsSource entirely. That gap let a crash-on-boot
    bug through: a `list[str]` field is treated as "complex" and JSON-decoded
    inside the source, before any validator runs, so a plain
    `CORS_ORIGINS=https://app.example.com` raised SettingsError.
    """

    def _deployable_env(self, monkeypatch: pytest.MonkeyPatch, **overrides: str) -> None:
        env = {
            "APP_ENV": "production",
            "APP_URL": "https://cloudguard.example.com",
            "SUPABASE_URL": "https://abc.supabase.co",
            "SUPABASE_PUBLISHABLE_KEY": "an-anon-key",
            "SUPABASE_JWT_SECRET": "a-real-secret",
            "AZURE_CONSENT_STATE_SECRET": "a-real-random-secret",
            "DATABASE_URL": "postgresql+asyncpg://cloudguard_app:pw@db.abc.supabase.co:5432/postgres",
            "DATABASE_OWNER_URL": "postgresql+asyncpg://postgres:pw@db.abc.supabase.co:5432/postgres",
            "REDIS_URL": "redis://default:pw@redis.railway.internal:6379",
            **overrides,
        }
        for key, value in env.items():
            monkeypatch.setenv(key, value)

    def test_a_single_origin_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """What anyone actually types into Railway."""
        self._deployable_env(monkeypatch, CORS_ORIGINS="https://cloudguard.vercel.app")
        settings = Settings()
        assert settings.cors_origins == ["https://cloudguard.vercel.app"]
        settings.raise_if_misconfigured()

    def test_comma_separated_origins_are_split(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._deployable_env(
            monkeypatch,
            CORS_ORIGINS="https://app.example.com, https://www.example.com",
        )
        assert Settings().cors_origins == [
            "https://app.example.com",
            "https://www.example.com",
        ]

    def test_a_json_list_still_works(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Anyone who already set the JSON form should not be broken by the fix."""
        self._deployable_env(
            monkeypatch, CORS_ORIGINS='["https://a.example.com","https://b.example.com"]'
        )
        assert Settings().cors_origins == ["https://a.example.com", "https://b.example.com"]

    def test_the_whole_environment_loads_from_env_vars(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End to end: every required variable supplied as a string, as Railway
        supplies them, produces a settings object that agrees to start."""
        self._deployable_env(monkeypatch, CORS_ORIGINS="https://cloudguard.vercel.app")
        settings = Settings()
        assert settings.config_problems() == []
        assert settings.app_env == "production"
        assert settings.database_url.startswith("postgresql+asyncpg://cloudguard_app:")
