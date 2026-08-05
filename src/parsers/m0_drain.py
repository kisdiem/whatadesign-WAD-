from __future__ import annotations

from pathlib import Path
from typing import Iterable

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

from src.common.schema import RawRecord, SyntaxParse, stable_record_id


class M0DrainParser:
    VERSION = "m0_drain_v1"

    def __init__(self) -> None:
        # Construct the config object directly so execution does not depend
        # on a process working directory or an untracked drain3.ini file.
        config = TemplateMinerConfig()
        config.drain_sim_th = 0.4
        config.drain_depth = 4
        self.miner = TemplateMiner(config=config)

    def parse(self, record: RawRecord) -> SyntaxParse:
        record_id = stable_record_id(record.dataset_id, record.source_file, record.source_line)
        payload = record.raw_payload if isinstance(record.raw_payload, str) else str(record.raw_payload)
        result = self.miner.add_log_message(payload)
        cluster_id = result.get("cluster_id")
        template_id = f"drain:{cluster_id}" if cluster_id is not None else "drain:unknown"
        return SyntaxParse(
            dataset_id=record.dataset_id,
            record_id=record_id,
            source_file=record.source_file,
            source_line=record.source_line,
            format="text",
            timestamp=record.raw_timestamp,
            fields={"template": result.get("template_mined", payload)},
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
