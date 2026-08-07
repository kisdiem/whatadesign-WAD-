from __future__ import annotations

import argparse
import json

import _bootstrap
from src.storage.migrations import migrate


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply versioned PostgreSQL storage migrations")
    parser.add_argument("--database-url", default=None, help="Defaults to DATABASE_URL")
    args = parser.parse_args()
    applied = migrate(args.database_url)
    print(json.dumps({"status": "OK", "applied_versions": applied}, indent=2))


if __name__ == "__main__":
    main()
