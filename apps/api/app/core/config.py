"""Application settings. Everything secret arrives via environment (SECURITY.md section 3)."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    supabase_jwt_secret: str = "local-dev-jwt-secret-change-me"
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
    azure_consent_state_secret: str = "local-dev-consent-secret-change-me"

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


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
