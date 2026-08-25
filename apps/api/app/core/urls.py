"""DSN helpers.

The same database is reached with two different drivers: asyncpg for the
request path, psycopg for Alembic (migrations are synchronous, and asyncpg
refuses multi-statement DDL because it always uses prepared statements).
"""


def to_sync_dsn(url: str) -> str:
    """Rewrite an async SQLAlchemy DSN to its synchronous psycopg equivalent."""
    for async_driver in ("+asyncpg", "+psycopg_async"):
        if async_driver in url:
            return url.replace(async_driver, "+psycopg")
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url
