FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

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

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
