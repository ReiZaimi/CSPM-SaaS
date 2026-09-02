"""CloudGuard API -- modular monolith.

Everything the product does lives in this one process (plus a Celery worker
sharing the same codebase). That is a deliberate choice: the product is a
scanner, a rule engine and a risk engine that all operate on the same data, and
splitting them across services would buy distributed-systems problems in
exchange for nothing the MVP needs.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import sentry_sdk
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.core.db import ping
from app.core.errors import (
    AppError,
    UnhandledErrorMiddleware,
    app_error_handler,
    envelope,
    http_error_handler,
    validation_error_handler,
)
from app.core.logging import configure_logging, get_logger

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()

    # Configuration is validated at import (app.core.config.get_settings), so
    # reaching this point already means the environment is complete. Logged so
    # a healthy boot is visible in the deploy logs, not just a failed one.
    log.info("config.validated", environment=settings.app_env)

    # Azure misconfiguration deliberately does not stop the API booting — it
    # breaks consent and nothing else, and refusing to start would cost the
    # whole dashboard to fix one button. But it was previously invisible until
    # a customer walked into it, so the operator who can actually fix it never
    # saw it. Warned here, where deploy logs are read.
    if settings.azure_configured and (problem := settings.azure_consent_problem):
        log.warning("azure.consent_misconfigured", problem=problem)

    if settings.sentry_dsn:
        sentry_sdk.init(dsn=settings.sentry_dsn, environment=settings.app_env)

    # Keep the rules table in step with the Python registry. The registry is the
    # source of truth; the table is a read-mirror for joins and the UI.
    from app.services.rule_sync import sync_rules_to_database

    try:
        synced = await sync_rules_to_database()
        log.info("rules.synced", count=synced)
    except Exception as exc:  # pragma: no cover -- never block startup on this
        log.warning("rules.sync_failed", error=str(exc))

    yield


app = FastAPI(
    title="CloudGuard API",
    version="0.1.0",
    description="Azure-first Cloud Security Posture Management.",
    lifespan=lifespan,
)

# Added before CORS on purpose, and the order is the whole point.
# ``add_middleware`` inserts at the front, so the last one added is the
# outermost -- which puts this one *inside* CORS, where the response it writes
# still picks up the access-control headers on the way back out. A bare
# ``Exception`` handler cannot do this: Starlette hands that to
# ``ServerErrorMiddleware``, outside everything, and the browser then refuses
# to read the 500 and reports a network failure instead.
app.add_middleware(UnhandledErrorMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_exception_handler(AppError, app_error_handler)  # type: ignore[arg-type]
app.add_exception_handler(HTTPException, http_error_handler)  # type: ignore[arg-type]
app.add_exception_handler(RequestValidationError, validation_error_handler)  # type: ignore[arg-type]

app.include_router(api_router)


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return envelope({"status": "ok", "environment": settings.app_env})


@app.get("/health/ready", tags=["meta"])
async def ready() -> dict:
    await ping()
    return envelope({"status": "ready", "database": "ok"})
