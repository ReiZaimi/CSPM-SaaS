"""Application settings. Everything secret arrives via environment (SECURITY.md section 3)."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Named so `production_config_problems()` can recognise them, rather than
# repeating the literals in two places where they could drift apart.
DEV_JWT_SECRET = "local-dev-jwt-secret-change-me"
DEV_CONSENT_SECRET = "local-dev-consent-secret-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    app_env: Literal["development", "test", "staging", "production"] = "development"
    app_url: str = "http://localhost:5173"
    api_url: str = "http://localhost:8000"
    log_level: str = "INFO"

    # --- Supabase -----------------------------------------------------------
    supabase_url: str = ""
    supabase_publishable_key: str = ""
    supabase_secret_key: str = ""
    supabase_jwt_secret: str = DEV_JWT_SECRET
    jwt_audience: str = "authenticated"

    # --- Database -----------------------------------------------------------
    # app connection == RLS-constrained. owner connection == migrations + worker.
    database_url: str = "postgresql+asyncpg://cloudguard_app:cloudguard_app@postgres:5432/cloudguard"
    database_owner_url: str = "postgresql+asyncpg://cloudguard:cloudguard@postgres:5432/cloudguard"
    db_echo: bool = False

    redis_url: str = "redis://redis:6379/0"

    # --- Azure: CloudGuard's own multi-tenant app identity ------------------
    azure_client_id: str = ""
    azure_client_secret: str = ""
    azure_tenant_id: str = ""
    azure_redirect_uri: str = "http://localhost:8000/api/v1/cloud-accounts/azure/consent/callback"
    azure_consent_state_secret: str = DEV_CONSENT_SECRET

    sentry_dsn: str = ""

    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])

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

        Without it the consent flow cannot run -- the API says so explicitly
        rather than failing deep inside a token request.
        """
        return bool(self.azure_client_id and self.azure_client_secret)

    def production_config_problems(self) -> list[str]:
        """Deployment mistakes that would leave a running server insecure.

        Every item here is something that works perfectly in local development
        and is a genuine vulnerability once the app is reachable from the
        internet. They are checked rather than trusted because each one fails
        *silently*: the server boots, the UI loads, and nothing looks wrong
        until someone forges a token.

        Returned rather than raised so the caller decides the severity --
        ``main.py`` refuses to start on any of these in production.
        """
        problems: list[str] = []

        if self.supabase_jwt_secret in {"", DEV_JWT_SECRET}:
            problems.append(
                "SUPABASE_JWT_SECRET is unset or still the development default. "
                "Every request's identity is verified against it, so a known "
                "value lets anyone mint a token for any user. Copy the real "
                "secret from Supabase: Project Settings > API > JWT Settings."
            )

        if self.azure_consent_state_secret in {"", DEV_CONSENT_SECRET}:
            problems.append(
                "AZURE_CONSENT_STATE_SECRET is unset or still the development "
                "default. It signs the Entra consent round-trip, so a known "
                "value lets an attacker bind their own tenant to someone "
                "else's cloud account. Set it to a random 32+ character string."
            )

        if any("localhost" in origin for origin in self.cors_origins):
            problems.append(
                "CORS_ORIGINS still contains localhost. Set it to your deployed "
                "frontend's URL, or the browser will block every API call."
            )

        if "localhost" in self.app_url:
            problems.append(
                "APP_URL still points at localhost. It is where the Entra admin "
                "consent callback sends the customer's browser back to, so a "
                "connected tenant would land on a dead link. Set it to your "
                "deployed frontend's URL."
            )

        if self.azure_configured and "localhost" in self.azure_redirect_uri:
            problems.append(
                "AZURE_REDIRECT_URI still points at localhost while an Azure app "
                "identity is configured. It must match the redirect URI "
                "registered on the Entra app exactly, or consent will fail."
            )

        if not self.supabase_url:
            problems.append(
                "SUPABASE_URL is unset. Without it the development sign-in "
                "route stays registered, which is not an authentication "
                "mechanism -- it mints tokens for any email given to it."
            )

        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
