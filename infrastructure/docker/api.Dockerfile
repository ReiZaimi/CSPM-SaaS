FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Without this, `import app` depends on whichever entrypoint happens to add the
# working directory to sys.path: uvicorn does (--app-dir defaults to "."),
# alembic does (prepend_sys_path in alembic.ini), but Celery is not guaranteed
# to -- so the worker would fail to start while the API looked fine.
ENV PYTHONPATH=/srv/apps/api

WORKDIR /srv

# WeasyPrint renders the PDF reports through pango/cairo rather than in pure
# Python, so those libraries have to be in the image. Without them the package
# imports and then fails at `dlopen` -- which looks like a code fault and is a
# missing apt package.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential curl \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libffi8 \
 && rm -rf /var/lib/apt/lists/*

# Dependency layer: copy only the manifest so edits to source don't reinstall.
# Runtime dependencies only -- pytest, mypy and ruff belong in CI, not in a
# deployed image, where they only add build time and attack surface.
COPY apps/api/pyproject.toml /srv/apps/api/pyproject.toml
RUN pip install --upgrade pip \
 && pip install -e /srv/apps/api

COPY apps/api /srv/apps/api
COPY database /srv/database

WORKDIR /srv/apps/api
EXPOSE 8000

# Railway's start command (railway.json) overrides this to run the migration
# first. This default stands in for any host that runs the image as-is, so it
# honors $PORT rather than assuming 8000.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
