FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# PYTHONPATH belongs in the image, not only in docker-compose.yml. Without it,
# `import app` depends on whichever entrypoint happens to add the working
# directory to sys.path: uvicorn does (--app-dir defaults to "."), alembic does
# (prepend_sys_path in alembic.ini), but Celery is not guaranteed to. That is
# why the worker started locally -- where compose sets PYTHONPATH -- and would
# fail on a host that doesn't.
ENV PYTHONPATH=/srv/apps/api

WORKDIR /srv

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential curl \
 && rm -rf /var/lib/apt/lists/*

# Dependency layer: copy only the manifest so edits to source don't reinstall.
COPY apps/api/pyproject.toml /srv/apps/api/pyproject.toml
RUN pip install --upgrade pip \
 && pip install -e "/srv/apps/api[dev]"

COPY apps/api /srv/apps/api
COPY database /srv/database

WORKDIR /srv/apps/api
EXPOSE 8000

# Local dev overrides this via docker-compose.yml's own `command:` (which adds
# --reload and the migration step). This default is what a host like Railway
# runs if no custom start command is set, so it deliberately has no --reload
# and honors $PORT rather than assuming 8000.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
