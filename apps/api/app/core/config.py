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

import json
import re
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Where Entra must send the browser back. Declared here because the redirect
# URI check below is the only thing that can catch a mismatch before a customer
# is already standing on Microsoft's error page; tests/unit/test_route_table.py
# asserts the API really does serve it.
_GUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
CONSENT_CALLBACK_PATH = "/api/v1/cloud-connections/azure/consent/callback"


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
    # Optional. Authenticates as cloudguard_worker, whose row-level security
    # arm trusts the organization a scan declares rather than a membership
    # lookup -- a background scan has no user to resolve one for.
    #
    # Left unset, the worker keeps using the owner connection, which bypasses
    # RLS entirely and relies on the pipeline's own filters. That is what it did
    # before this existed, so not setting it changes nothing; setting it moves
    # the guarantee from our code into PostgreSQL.
    database_worker_url: str = ""
    db_echo: bool = False

    @property
    def worker_is_constrained(self) -> bool:
        """Whether the worker's tenancy is enforced by the database."""
        return bool(self.database_worker_url)

    @property
    def scan_database_url(self) -> str:
        """The connection a scan's own work runs on."""
        return self.database_worker_url or self.database_owner_url

    redis_url: str = ""

    # --- Azure: CloudGuard's own multi-tenant app identity ------------------
    azure_client_id: str = ""
    azure_client_secret: str = ""
    azure_tenant_id: str = ""
    azure_redirect_uri: str = ""
    azure_consent_state_secret: str = ""

    sentry_dsn: str = ""

    # NoDecode is load-bearing. pydantic-settings treats any list field as
    # "complex" and runs json.loads() on the raw environment value *inside the
    # settings source*, before field validators ever run -- so a perfectly
    # reasonable CORS_ORIGINS=https://app.example.com raised SettingsError and
    # crashed the process on boot. NoDecode hands the raw string to the
    # validator below instead.
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        """Accept a comma-separated list, a JSON array, or a real list.

        Comma-separated is what a person types into a dashboard field; the JSON
        form is what pydantic-settings would otherwise have required, and is
        still accepted so an existing deployment is not broken by this fix.
        """
        if not isinstance(v, str):
            return v
        text = v.strip()
        if text.startswith("["):
            try:
                return json.loads(text)
            except ValueError:
                pass  # fall through and treat it as a plain string
        return [item.strip() for item in text.split(",") if item.strip()]

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

    @property
    def azure_consent_problem(self) -> str | None:
        """Why this deployment cannot start a consent flow, if it cannot.

        Separate from ``azure_configured`` because having an app identity is
        not the same as being able to use it. The redirect URI is checked here
        rather than left to Entra, which rejects a malformed one with
        ``AADSTS90013: Invalid input received from the user`` -- a message that
        names neither the parameter nor the deployment, on Microsoft's domain,
        after the administrator has already been sent away. The single most
        common cause is a value pasted from the deployment guide with its
        ``<your-railway-api-domain>`` placeholder still in it.
        """
        if not self.azure_configured:
            return (
                "The server has no Entra application identity. Set "
                "AZURE_CLIENT_ID and AZURE_CLIENT_SECRET "
                "(docs/AZURE_INTEGRATION.md 2.1)."
            )

        # Azure Portal lists a secret's Value and its Secret ID side by side,
        # and copies the ID far more readily: the Value is shown once, at
        # creation, and is never recoverable afterwards. Pasting the ID is
        # therefore the single easiest mistake to make here, and Entra only
        # says so as AADSTS7000215 -- deep inside a token request, long after
        # a customer has already involved their Global Administrator. A secret
        # value is never a bare GUID, so this is decidable before anyone is
        # sent anywhere.
        if _GUID.fullmatch(self.azure_client_secret.strip()):
            return (
                "AZURE_CLIENT_SECRET looks like a Secret ID, not a secret "
                "value. In Azure Portal the Value column is the one to copy, "
                "and it is only shown when the secret is created -- if it has "
                "been lost, add a new client secret and copy its Value."
            )
        if not _GUID.fullmatch(self.azure_client_id.strip()):
            return (
                f'AZURE_CLIENT_ID is "{self.azure_client_id}", which is not a '
                "GUID. It should be the Application (client) ID from the app "
                "registration's Overview page."
            )

        uri = self.azure_redirect_uri
        if not uri:
            return (
                "AZURE_REDIRECT_URI is not set. It must match the redirect URI "
                "registered on the Entra app exactly."
            )
        if "<" in uri or ">" in uri:
            return (
                f'AZURE_REDIRECT_URI still contains a placeholder ("{uri}"). '
                "Replace it with this API's real public URL."
            )
        if not uri.startswith("https://"):
            return (
                f'AZURE_REDIRECT_URI is "{uri}", which is not an https:// URL. '
                "Entra refuses any other scheme for a Web redirect."
            )
        if not uri.endswith(CONSENT_CALLBACK_PATH):
            return (
                f'AZURE_REDIRECT_URI is "{uri}", which does not end in '
                f"{CONSENT_CALLBACK_PATH}. Consent will return to a path this "
                "API does not serve."
            )
        return None

    @property
    def azure_consent_ready(self) -> bool:
        return self.azure_consent_problem is None

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
        # Deliberately NOT required. Supabase signs with asymmetric keys
        # (ES256/RS256) by default now, and those projects have no shared secret
        # at all -- the public keys come from the JWKS endpoint derived from
        # SUPABASE_URL. Only legacy HS256 projects need this, and
        # app.core.security says so precisely if such a token arrives without it.
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

        # Only the *missing* case is fatal, as it always has been: an Azure
        # identity with no redirect URI is an incomplete deployment. A malformed
        # one is reported through `azure_consent_problem` and surfaced in the
        # connection wizard instead -- it breaks consent and nothing else, and
        # refusing to boot over it would cost a customer their whole dashboard
        # to fix one button.
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
