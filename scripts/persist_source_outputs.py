from __future__ import annotations

import argparse
import json

import _bootstrap
from src.storage.persist import persist_work_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Persist strict V3 source outputs into PostgreSQL")
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--database-url", default=None, help="Defaults to DATABASE_URL")
    parser.add_argument("--no-migrate", action="store_true")
    args = parser.parse_args()
    result = persist_work_dir(args.work_dir, args.database_url, auto_migrate=not args.no_migrate)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
