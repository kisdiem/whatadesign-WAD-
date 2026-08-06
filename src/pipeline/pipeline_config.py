from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

import yaml


_ENV = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _resolve(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {key: _resolve(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve(item) for item in value]
    return value


def load_config(path: str | Path) -> tuple[dict[str, Any], str]:
    target = Path(path)
    config = _resolve(yaml.safe_load(target.read_text(encoding="utf-8")) or {})
    encoded = yaml.safe_dump(config, sort_keys=True).encode("utf-8")
    return config, hashlib.sha256(encoded).hexdigest()


def save_resolved_config(config: dict[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml.safe_dump(config, sort_keys=True), encoding="utf-8")
    return target
