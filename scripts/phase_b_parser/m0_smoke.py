from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.parsers.m0_drain import M0DrainParser
from src.common.audit import append_operation


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    path = Path(sys.argv[1])
    parser = M0DrainParser()
    rows = list(parser.parse_lines("loghub_2_0", path, limit=2000))
    output = root / "outputs/source_validation/m0_smoke.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    result = {"smoke_status": "passed", "rows": len(rows), "templates": parser.catalog()["templates"], "ait_accessed": False}
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    append_operation(root / "logs/operations.jsonl", "m0_smoke", "completed", **result, input_path=str(path))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
