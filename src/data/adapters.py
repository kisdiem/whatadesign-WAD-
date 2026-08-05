from __future__ import annotations

import csv
import gzip
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


class LanlEventAdapter:
    """Read one of LANL Cyber1's de-identified CSV event streams.

    The files are intentionally kept as source-domain records.  The redteam
    stream is not converted into AIT labels here; downstream evaluation owns
    that decision and must record it in the release manifest.
    """

    dataset_id = "lanl_comprehensive"
    _schemas = {
        "auth": ("time", "source_user", "destination_user", "source_computer", "destination_computer", "authentication_type", "logon_type", "authentication_orientation", "status"),
        "proc": ("time", "user", "computer", "process", "action"),
        "flows": ("time", "duration", "source_computer", "source_port", "destination_computer", "destination_port", "protocol", "packet_count", "byte_count"),
        "dns": ("time", "source_computer", "resolved_computer"),
        "redteam": ("time", "user", "source_computer", "destination_computer"),
    }

    def read(self, path: Path, limit: int = 0) -> AdapterResult:
        kind = path.name.removesuffix(".gz").removesuffix(".txt")
        columns = self._schemas.get(kind)
        if columns is None:
            return AdapterResult(self.dataset_id, (), "blocked", (f"unsupported LANL file: {path.name}",))

        records: list[RawRecord] = []
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8", errors="replace", newline="") as stream:
            for row_no, row in enumerate(csv.reader(stream), 1):
                if not row or not any(cell.strip() for cell in row):
                    continue
                payload = dict(zip(columns, row, strict=False))
                records.append(RawRecord(self.dataset_id, str(path), row_no, payload.get("time"), payload, f"lanl_{kind}_v1"))
                if limit and len(records) >= limit:
                    break
        return AdapterResult(self.dataset_id, tuple(records), "ok")


def adapter_for(dataset_id: str):
    adapters = {
        "loghub_2_0": LogHubTextAdapter,
        "sandworm_flow": SandwormFlowAdapter,
        "evtx_attack_samples": EvtxAdapter,
        "lanl_comprehensive": LanlEventAdapter,
    }
    try:
        return adapters[dataset_id]()
    except KeyError as exc:
        raise ValueError(f"no adapter registered for {dataset_id}") from exc
