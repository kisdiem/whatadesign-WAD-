from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
from src.common.schema import SyntaxParse


@dataclass
class QuarantineSink:
    path: Path

    def write(self, item: SyntaxParse) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(item.to_dict(), ensure_ascii=True) + "\n")
