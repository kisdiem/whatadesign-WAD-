from __future__ import annotations

import argparse
import json

import _bootstrap
from src.detection.log_index import build_log_index


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a paginated SQLite index for processed real logs.")
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--max-records-per-root", type=int, default=200_000)
    args = parser.parse_args()
    result = build_log_index(args.root, args.database, max_records_per_root=args.max_records_per_root)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
