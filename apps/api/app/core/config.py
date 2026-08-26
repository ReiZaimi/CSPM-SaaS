"""Application settings.

CloudGuard runs in one place: a managed cloud environment (Supabase for
PostgreSQL and Auth, Railway for the API and worker, Vercel for the frontend).
There is deliberately no local-development mode and no localhost defaults --
every value below has to be supplied by the environment, and the app refuses to
start if any of them is missing or obviously wrong.

That refusal is the point. Every setting checked here is one that would let the
process boot, look healthy, and be trivially exploitable: a known JWT secret
lets anyone mint a token for any user; a stale APP_URL strands a customer
mid-consent. Failing the deploy is the kinder outcome for a security product.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigurationError(RuntimeError):
    """Raised when the environment cannot support a running deployment."""


class Settings(BaseSettings):
    # No env_file: configuration comes from the platform's environment
    # variables, never from a file sitting next to the code.
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    # Defaults to production so a forgotten variable fails closed rather than
    # silently relaxing the checks below. "test" is the only value that skips
    # them, and it exists for CI.
    app_env: Literal["test", "staging", "production"] = "production"

    app_url: str = ""
    api_url: str = ""
    log_level: str = "INFO"

    # --- Supabase -----------------------------------------------------------
    supabase_url: str = ""
    supabase_publishable_key: str = ""
    supabase_secret_key: str = ""
    supabase_jwt_secret: str = ""
    jwt_audience: str = "authenticated"

    # --- Database -----------------------------------------------------------
    # app connection == RLS-constrained. owner connection == migrations.
    database_url: str = ""
    database_owner_url: str = ""
    db_echo: bool = False

    redis_url: str = ""

    # --- Azure: CloudGuard's own multi-tenant app identity ------------------
    azure_client_id: str = ""
    azure_client_secret: str = ""
    azure_tenant_id: str = ""
    azure_redirect_uri: str = ""
    azure_consent_state_secret: str = ""

    sentry_dsn: str = ""

    cors_origins: list[str] = Field(default_factory=list)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def azure_configured(self) -> bool:
        """True when CloudGuard's own Entra app identity is present.

        Optional: everything up to the Connections screen works without it, so
        a deployment that has not reached the Entra registration step is not
        broken, just not yet able to scan.
        """
        return bool(self.azure_client_id and self.azure_client_secret)

    def config_problems(self) -> list[str]:
        """Everything wrong with this environment, in plain language.

        Returned rather than raised so callers choose the severity, and so the
        whole list surfaces at once -- finding four missing variables one
        redeploy at a time is its own kind of cruelty.
        """
        problems: list[str] = []

        def require(value: str, name: str, why: str) -> None:
            if not value:
                problems.append(f"{name} is not set. {why}")

        require(
            self.database_url,
            "DATABASE_URL",
            "This is the RLS-constrained connection every request uses. It must "
            "authenticate as cloudguard_app, not postgres.",
        )
        require(
            self.database_owner_url,
            "DATABASE_OWNER_URL",
            "Alembic needs the owning role to create tables and RLS policies. "
            "This one authenticates as postgres.",
        )
        require(
            self.redis_url,
            "REDIS_URL",
            "Celery uses it to queue scans; without it a scan can be requested "
            "but never runs.",
        )
        require(
            self.supabase_url,
            "SUPABASE_URL",
            "Your Supabase project URL, e.g. https://<ref>.supabase.co.",
        )
        require(
            self.supabase_publishable_key,
            "SUPABASE_PUBLISHABLE_KEY",
            "The anon key from Supabase: Project Settings > API.",
        )
        require(
            self.supabase_jwt_secret,
            "SUPABASE_JWT_SECRET",
            "Every request's identity is verified against it. Supabase: Project "
            "Settings > API > JWT Settings.",
        )
        require(
            self.azure_consent_state_secret,
            "AZURE_CONSENT_STATE_SECRET",
            "It signs the Entra consent round-trip, so it must be secret even "
            "before a tenant is connected. Generate with: openssl rand -hex 32.",
        )
        require(
            self.app_url,
            "APP_URL",
            "Your deployed frontend's URL. The Entra consent callback sends the "
            "customer's browser back to it.",
        )
        if not self.cors_origins:
            problems.append(
                "CORS_ORIGINS is not set. Set it to your deployed frontend's URL, "
                "or the browser will block every API call."
            )

        # A localhost value here means a local default leaked into a deployment
        # -- it would point a real customer at their own machine.
        for name, value in (
            ("APP_URL", self.app_url),
            ("API_URL", self.api_url),
            ("DATABASE_URL", self.database_url),
            ("DATABASE_OWNER_URL", self.database_owner_url),
            ("REDIS_URL", self.redis_url),
        ):
            if value and ("localhost" in value or "127.0.0.1" in value):
                problems.append(
                    f"{name} points at localhost. There is no local environment "
                    "-- this must be the deployed address."
                )

        if any("localhost" in origin for origin in self.cors_origins):
            problems.append(
                "CORS_ORIGINS contains localhost. Set it to your deployed "
                "frontend's URL."
            )

        if self.azure_configured and not self.azure_redirect_uri:
            problems.append(
                "AZURE_REDIRECT_URI is not set while an Azure app identity is "
                "configured. It must match the redirect URI registered on the "
                "Entra app exactly, or consent will fail."
            )

        return problems

    def raise_if_misconfigured(self) -> None:
        if self.app_env == "test":
            return
        problems = self.config_problems()
        if problems:
            raise ConfigurationError(
                "CloudGuard cannot start: the environment is incomplete.\n  - "
                + "\n  - ".join(problems)
            )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    # Validated at import, before any database engine is constructed, so a
    # missing variable produces this explanation rather than a connection error
    # thrown from somewhere much less obvious.
    settings.raise_if_misconfigured()
    return settings


settings = get_settings()
