from __future__ import annotations

import csv
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from src.common.schema import RawRecord


@dataclass(frozen=True)
class AdapterResult:
    dataset_id: str
    records: tuple[RawRecord, ...]
    status: str
    errors: tuple[str, ...] = ()


class LogHubTextAdapter:
    dataset_id = "loghub_2_0"

    def read(self, path: Path, limit: int = 0) -> AdapterResult:
        records: list[RawRecord] = []
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line_no, line in enumerate(stream, 1):
                if line.strip():
                    records.append(RawRecord(self.dataset_id, str(path), line_no, None, line.rstrip("\r\n"), "raw_text_v1"))
                if limit and len(records) >= limit:
                    break
        return AdapterResult(self.dataset_id, tuple(records), "ok")


class SandwormFlowAdapter:
    dataset_id = "sandworm_flow"

    def read(self, path: Path, limit: int = 0) -> AdapterResult:
        records: list[RawRecord] = []
        with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
            for row_no, row in enumerate(csv.DictReader(stream), 2):
                payload = dict(row)
                timestamp = payload.get("timestamp") or payload.get("Timestamp") or payload.get("StartTime")
                records.append(RawRecord(self.dataset_id, str(path), row_no, timestamp, payload, "sandworm_csv_v1"))
                if limit and len(records) >= limit:
                    break
        return AdapterResult(self.dataset_id, tuple(records), "ok")


class EvtxAdapter:
    dataset_id = "evtx_attack_samples"

    def read(self, path: Path, limit: int = 0) -> AdapterResult:
        try:
            from Evtx.Evtx import Evtx  # type: ignore
        except ImportError:
            return AdapterResult(self.dataset_id, (), "blocked", ("python-evtx is not installed",))
        records: list[RawRecord] = []
        with Evtx(str(path)) as log:
            for line_no, record in enumerate(log.records(), 1):
                payload = record.xml()
                records.append(RawRecord(self.dataset_id, str(path), line_no, None, payload, "evtx_xml_v1"))
                if limit and len(records) >= limit:
                    break
        return AdapterResult(self.dataset_id, tuple(records), "ok")


def adapter_for(dataset_id: str):
    adapters = {"loghub_2_0": LogHubTextAdapter, "sandworm_flow": SandwormFlowAdapter, "evtx_attack_samples": EvtxAdapter}
    try:
        return adapters[dataset_id]()
    except KeyError as exc:
        raise ValueError(f"no adapter registered for {dataset_id}") from exc
