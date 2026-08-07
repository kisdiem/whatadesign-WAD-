from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import _bootstrap
from src.storage.persist import persist_work_dir


def _extract_option(argv: list[str], name: str) -> str | None:
    for index, value in enumerate(argv):
        if value == name and index + 1 < len(argv):
            return argv[index + 1]
        prefix = name + "="
        if value.startswith(prefix):
            return value[len(prefix):]
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the existing strict source pipeline, then persist facts/results to PostgreSQL",
        add_help=False,
    )
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--no-migrate", action="store_true")
    storage_args, pipeline_args = parser.parse_known_args()

    work_dir = _extract_option(pipeline_args, "--work-dir")
    if not work_dir:
        raise SystemExit("--work-dir is required by the source pipeline")

    command = [sys.executable, str(Path(__file__).with_name("run_source_v3_pipeline.py")), *pipeline_args]
    subprocess.run(command, check=True)
    persisted = persist_work_dir(
        work_dir,
        storage_args.database_url,
        auto_migrate=not storage_args.no_migrate,
    )
    print(json.dumps({"pipeline": "COMPLETED", "storage": persisted}, indent=2, default=str))


if __name__ == "__main__":
    main()
