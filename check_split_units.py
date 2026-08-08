from __future__ import annotations

import importlib.util
import os
import sys
from collections import defaultdict

sys.path.insert(0, "scripts")
spec = importlib.util.spec_from_file_location("source_runner", "scripts/run_source_v3_pipeline.py")
runner = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(runner)

config, _ = runner.load_config("configs/v3/source_training.yaml")
records, labels, errors = runner.discover_records(config, runner.Path("outputs/source/split_probe"), 500)
groups = defaultdict(lambda: [0, 0])
for record in records:
    key = f"{record.source_file}::line_block_{(record.source_line - 1) // 20:08d}"
    groups[key][0] += 1
    groups[key][1] += labels[record.raw_record_id]
positive = [(key, values) for key, values in groups.items() if values[1] > 0]
print({"records": len(records), "errors": errors, "units": len(groups), "positive_units": len(positive), "positive_records": sum(values[1] for _, values in positive)})
for key, values in sorted(positive, key=lambda item: (-item[1][1], item[0])):
    print(values[0], values[1], key)
