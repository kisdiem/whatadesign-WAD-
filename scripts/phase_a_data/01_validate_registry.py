from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.common.audit import append_operation
from src.registry.loader import load_registry


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    registry = root / "configs/data/data_registry.yaml"
    document = load_registry(registry)
    output = root / "outputs/source_validation/registry_validation.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    result = {"validation_status": "passed", "datasets": len(document["datasets"]), "ait_accessed": False}
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    append_operation(root / "logs/operations.jsonl", "validate_registry", "completed", **result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
