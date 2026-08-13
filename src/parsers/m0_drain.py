from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

from src.common.schema import RawRecord, SyntaxParse, stable_record_id


class M0DrainParser:
    VERSION = "m0_drain_v2"
    SAFE_CONSTANTS = frozenset({
        "success", "failure", "failed", "start", "end", "login", "logout",
        "logon", "logoff", "read", "write", "open", "close", "allow", "deny",
        "accept", "reject", "tcp", "udp", "dns", "http", "https", "powershell",
    })
    _IP = re.compile(r"(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9])")
    _UUID = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
    _HEX = re.compile(r"(?i)\b0x[0-9a-f]{6,}\b")
    _NUMBER = re.compile(r"(?<![A-Za-z_])\d+(?![A-Za-z_])")

    def __init__(self) -> None:
        # Construct the config object directly so execution does not depend
        # on a process working directory or an untracked drain3.ini file.
        config = TemplateMinerConfig()
        config.drain_sim_th = 0.4
        config.drain_depth = 4
        self.miner = TemplateMiner(config=config)

    @classmethod
    def safe_mask(cls, payload: str) -> str:
        """Mask volatile identifiers while preserving security constants."""
        masked = cls._IP.sub("<IP>", payload)
        masked = cls._UUID.sub("<UUID>", masked)
        masked = cls._HEX.sub("<HEX>", masked)

        def replace_number(match: re.Match[str]) -> str:
            token = match.group(0)
            start = match.start()
            prefix = masked[max(0, start - 24):start].lower()
            if any(prefix.endswith(key) for key in ("eventid=", "status=", "result=", "action=")):
                return token
            return "<NUM>"

        return cls._NUMBER.sub(replace_number, masked)

    @staticmethod
    def template_fingerprint(template: str) -> str:
        canonical = " ".join(template.split()).strip().lower()
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def parse(self, record: RawRecord) -> SyntaxParse:
        record_id = stable_record_id(record.dataset_id, record.source_file, record.source_line)
        payload = record.raw_payload if isinstance(record.raw_payload, str) else str(record.raw_payload)
        result = self.miner.add_log_message(self.safe_mask(payload))
        cluster_id = result.get("cluster_id")
        template_id = f"drain:{cluster_id}" if cluster_id is not None else "drain:unknown"
        return SyntaxParse(
            dataset_id=record.dataset_id,
            record_id=record_id,
            source_file=record.source_file,
            source_line=record.source_line,
            format="text",
            timestamp=record.raw_timestamp,
            fields={
                "template": result.get("template_mined", payload),
                "template_fingerprint": self.template_fingerprint(result.get("template_mined", payload)),
            },
            template_id=template_id,
            parse_confidence=float(result.get("change_type", 0) != 2),
            raw_record_ref=f"{record.source_file}:{record.source_line}",
        )

    def parse_lines(self, dataset_id: str, path: Path, limit: int = 0) -> Iterable[SyntaxParse]:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line_no, line in enumerate(stream, 1):
                line = line.rstrip("\r\n")
                if not line.strip():
                    continue
                yield self.parse(RawRecord(dataset_id, str(path), line_no, None, line, self.VERSION))
                if limit and line_no >= limit:
                    break

    def catalog(self) -> dict:
        clusters = self.miner.drain.clusters
        return {
            "schema_version": self.VERSION,
            "templates": len(clusters),
            "clusters": [
                {
                    "cluster_id": cluster.cluster_id,
                    "log_template": cluster.get_template(),
                    "size": cluster.size,
                }
                for cluster in clusters
            ],
        }

    def save_cache(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = self.catalog()
        payload["cache_version"] = "m0_template_cache_v1"
        path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")

    @staticmethod
    def load_cache(path: Path) -> dict:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("cache_version") != "m0_template_cache_v1":
            raise ValueError("unsupported M0 cache version")
        return payload
