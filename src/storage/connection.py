from __future__ import annotations

import os
from typing import Any


class StorageDependencyError(RuntimeError):
    pass


def resolve_database_url(value: str | None = None) -> str:
    url = value or os.getenv("DATABASE_URL")
    if not url:
        raise ValueError("PostgreSQL DATABASE_URL is required")
    if not url.startswith(("postgresql://", "postgres://")):
        raise ValueError("DATABASE_URL must use postgresql:// or postgres://")
    return url


def connect_postgres(database_url: str | None = None):
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise StorageDependencyError(
            "PostgreSQL storage requires psycopg 3; install requirements-storage.txt"
        ) from exc
    return psycopg.connect(resolve_database_url(database_url), row_factory=dict_row)


def jsonb(value: Any):
    try:
        from psycopg.types.json import Jsonb
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise StorageDependencyError(
            "PostgreSQL storage requires psycopg 3; install requirements-storage.txt"
        ) from exc
    return Jsonb(value)
