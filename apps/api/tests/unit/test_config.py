"""The configuration guard.

This runs once per deploy and never anywhere else, which is exactly why it
needs tests: a mistake here is invisible until the day it matters, and its
whole job is to catch mistakes that are otherwise invisible.

Each test constructs Settings directly with explicit values. The env is cleared
first so a variable set in CI (which sets DATABASE_URL and friends for the
integration suite) cannot mask a missing-value assertion.
"""

import pytest

from app.core.config import CONSENT_CALLBACK_PATH, ConfigurationError, Settings

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


class TestAzureConsentReadiness:
    """The redirect URI is checked here so a customer never meets AADSTS90013.

    Entra rejects a malformed redirect_uri with "Invalid input received from
    the user" -- on Microsoft's domain, naming neither the parameter nor the
    deployment, after the administrator has already been sent away. Every case
    below produced exactly that, indistinguishably.
    """

    # Shaped like the real thing, because the checks now read the shape: a
    # client id is a GUID and a secret value is emphatically not one.
    CLIENT_ID = "8f39c34c-e523-4914-89ca-d6de1a8691ab"
    SECRET_VALUE = "aBc7Q~exampleSecretValue.With-Punctuation_123"

    def azure(self, uri: str, **overrides: str) -> Settings:
        return settings_with(
            azure_client_id=overrides.get("client_id", self.CLIENT_ID),
            azure_client_secret=overrides.get("client_secret", self.SECRET_VALUE),
            azure_redirect_uri=uri,
        )

    def test_a_secret_id_pasted_instead_of_the_value_is_caught(self) -> None:
        """The mistake Azure Portal invites.

        It lists Value and Secret ID side by side, and only the ID survives
        past the moment of creation -- so the ID is what people still have to
        copy later. Entra reports it as AADSTS7000215 from inside a token
        request, three steps into onboarding and after a Global Administrator
        has already been involved. A secret value is never a bare GUID, so it
        is decidable here instead.
        """
        s = self.azure(
            f"https://api.example.com{CONSENT_CALLBACK_PATH}",
            client_secret="8f39c34c-e523-4914-89ca-d6de1a8691ab",
        )
        problem = s.azure_consent_problem or ""
        assert "Secret ID" in problem
        assert "Value column" in problem

    def test_a_client_id_that_is_not_a_guid_is_caught(self) -> None:
        s = self.azure(
            f"https://api.example.com{CONSENT_CALLBACK_PATH}", client_id="app-id"
        )
        assert "not a GUID" in (s.azure_consent_problem or "")

    def test_a_real_looking_secret_value_is_accepted(self) -> None:
        """The check must not reject the credential it is protecting."""
        s = self.azure(f"https://api.example.com{CONSENT_CALLBACK_PATH}")
        assert s.azure_consent_problem is None

    def test_a_correct_redirect_uri_is_ready(self) -> None:
        s = self.azure(f"https://api.example.com{CONSENT_CALLBACK_PATH}")
        assert s.azure_consent_problem is None
        assert s.azure_consent_ready is True

    def test_an_unsubstituted_placeholder_is_caught(self) -> None:
        """The most common failure: the deployment guide's own example, pasted
        with `<your-railway-api-domain>` left in it."""
        s = self.azure(f"https://<your-railway-api-domain>{CONSENT_CALLBACK_PATH}")
        assert "placeholder" in (s.azure_consent_problem or "")

    def test_a_non_https_uri_is_caught(self) -> None:
        s = self.azure(f"http://api.example.com{CONSENT_CALLBACK_PATH}")
        assert "https://" in (s.azure_consent_problem or "")

    def test_the_pre_connections_callback_path_is_caught(self) -> None:
        """The path moved when connections replaced per-subscription accounts.
        A deployment still on the old value would fail only at consent time."""
        s = self.azure(
            "https://api.example.com/api/v1/cloud-accounts/azure/consent/callback"
        )
        assert CONSENT_CALLBACK_PATH in (s.azure_consent_problem or "")

    def test_a_missing_identity_is_reported_before_the_uri(self) -> None:
        assert "AZURE_CLIENT_ID" in (settings_with().azure_consent_problem or "")

    def test_a_malformed_uri_does_not_stop_the_api_booting(self) -> None:
        """It breaks consent and nothing else. Refusing to boot would cost a
        customer their dashboard to fix one button."""
        s = self.azure(f"https://<placeholder>{CONSENT_CALLBACK_PATH}")
        assert s.azure_consent_problem is not None
        assert not [p for p in s.config_problems() if "AZURE_REDIRECT_URI" in p]
