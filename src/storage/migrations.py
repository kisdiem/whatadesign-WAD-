from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from src.storage.connection import connect_postgres


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: Path
    checksum: str


def migration_root() -> Path:
    return Path(__file__).resolve().parents[2] / "migrations" / "postgres"


def discover_migrations(root: Path | None = None) -> list[Migration]:
    base = root or migration_root()
    rows: list[Migration] = []
    for path in sorted(base.glob("*.sql")):
        prefix, _, name = path.stem.partition("_")
        if not prefix.isdigit() or not name:
            raise ValueError(f"invalid migration filename: {path.name}")
        payload = path.read_bytes()
        rows.append(Migration(int(prefix), name, path, hashlib.sha256(payload).hexdigest()))
    versions = [row.version for row in rows]
    if len(set(versions)) != len(versions):
        raise ValueError("duplicate PostgreSQL migration versions")
    return rows


def _bootstrap(connection) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                checksum TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
    connection.commit()


def apply_migrations(connection, migrations: Iterable[Migration] | None = None) -> list[int]:
    _bootstrap(connection)
    pending = list(migrations or discover_migrations())
    with connection.cursor() as cursor:
        cursor.execute("SELECT version, checksum FROM schema_migrations")
        applied = {int(row["version"]): str(row["checksum"]) for row in cursor.fetchall()}

    changed: list[int] = []
    for migration in pending:
        previous = applied.get(migration.version)
        if previous is not None:
            if previous != migration.checksum:
                raise RuntimeError(
                    f"migration {migration.version:03d} checksum changed after application"
                )
            continue
        sql = migration.path.read_text(encoding="utf-8")
        try:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT pg_advisory_xact_lock(hashtext('whatadesign-v3-storage-migrations'))"
                    )
                    cursor.execute("SELECT checksum FROM schema_migrations WHERE version=%s", (migration.version,))
                    concurrent = cursor.fetchone()
                    if concurrent is not None:
                        if str(concurrent["checksum"]) != migration.checksum:
                            raise RuntimeError(
                                f"migration {migration.version:03d} checksum changed after application"
                            )
                        continue
                    cursor.execute(sql)
                    cursor.execute(
                        "INSERT INTO schema_migrations(version,name,checksum) VALUES(%s,%s,%s)",
                        (migration.version, migration.name, migration.checksum),
                    )
        except BaseException:
            connection.rollback()
            raise
        changed.append(migration.version)
    return changed


def migrate(database_url: str | None = None) -> list[int]:
    connection = connect_postgres(database_url)
    try:
        return apply_migrations(connection)
    finally:
        connection.close()
