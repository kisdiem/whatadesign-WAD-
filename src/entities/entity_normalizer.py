from __future__ import annotations
import os
import re


def normalize(value: str, entity_type: str, platform: str = "unknown") -> str:
    value = str(value).strip()
    if entity_type in {"user", "domain", "service"}:
        return value.casefold()
    if entity_type == "file":
        return value.replace("\\", "/") if platform.lower() == "linux" else value.replace("/", "\\").casefold()
    if entity_type == "ip":
        return value
    return re.sub(r"\s+", " ", value)
