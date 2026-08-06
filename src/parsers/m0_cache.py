from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CacheManifest:
    parser_version: str
    configuration_hash: str
    creation_time: str
    source_scope: str


class M0Cache:
    def __init__(self, root: str | Path, manifest: CacheManifest) -> None:
        self.root = Path(root)
        self.manifest = manifest

    def save(self, key: str, value: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / f"{key}.json").write_text(json.dumps(value, ensure_ascii=True), encoding="utf-8")
        (self.root / "manifest.json").write_text(json.dumps(asdict(self.manifest), indent=2), encoding="utf-8")

    def load(self, key: str) -> dict[str, Any] | None:
        path = self.root / f"{key}.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    @staticmethod
    def configuration_hash(config: dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()

    @classmethod
    def manifest_for(cls, parser_version: str, config: dict[str, Any], source_scope: str) -> CacheManifest:
        return CacheManifest(parser_version, cls.configuration_hash(config), datetime.now(timezone.utc).isoformat(), source_scope)
