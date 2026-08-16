from __future__ import annotations

import csv
import gzip
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Protocol

from src.common.schema import RawRecord, stable_record_id


@dataclass(frozen=True)
class AdapterResult:
    dataset_id: str
    records: tuple[RawRecord, ...]
    status: str = "ok"
    errors: tuple[str, ...] = ()


class SourceAdapter(Protocol):
    dataset_id: str

    def read(self, path: Path, limit: int = 0) -> AdapterResult: ...


def _record(
    dataset_id: str,
    path: Path,
    line: int,
    timestamp: str | None,
    payload: str | dict[str, str],
    adapter_version: str,
) -> RawRecord:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True) if isinstance(payload, dict) else payload
    return RawRecord(
        dataset_id=dataset_id,
        source_file=str(path),
        source_line=line,
        raw_timestamp=timestamp,
        raw_payload=payload,
        parser_version=adapter_version,
        adapter_version=adapter_version,
        raw_record_id=stable_record_id(dataset_id, str(path), line),
        source_hash=hashlib.sha256(encoded.encode("utf-8", "replace")).hexdigest(),
        ingestion_metadata={"compressed": path.suffix.lower() == ".gz"},
    )


def _text_stream(path: Path) -> IO[str]:
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace", newline="")


class LogHubTextAdapter:
    dataset_id = "loghub_2_0"
    version = "loghub_text_v1"
    _timestamp = re.compile(
        r"^(?P<value>(?:\d{10}(?:\.\d+)?)|(?:\d{4}-\d{2}-\d{2}[T ][^\s]+))"
    )

    def read(self, path: Path, limit: int = 0) -> AdapterResult:
        records: list[RawRecord] = []
        try:
            with _text_stream(path) as stream:
                for line_number, value in enumerate(stream, start=1):
                    text = value.rstrip("\r\n")
                    if not text.strip():
                        continue
                    match = self._timestamp.search(text)
                    records.append(_record(
                        self.dataset_id,
                        path,
                        line_number,
                        match.group("value") if match else None,
                        text,
                        self.version,
                    ))
                    if limit and len(records) >= limit:
                        break
        except (OSError, UnicodeError) as error:
            return AdapterResult(self.dataset_id, (), "error", (str(error),))
        return AdapterResult(self.dataset_id, tuple(records))


class SandwormFlowAdapter:
    dataset_id = "sandworm_flow"
    version = "sandworm_csv_v1"

    @staticmethod
    def _timestamp(row: dict[str, str]) -> str | None:
        lowered = {key.lower(): value for key, value in row.items() if key is not None}
        return next((lowered[key] for key in ("timestamp", "starttime", "time", "ts") if lowered.get(key)), None)

    def read(self, path: Path, limit: int = 0) -> AdapterResult:
        records: list[RawRecord] = []
        try:
            with _text_stream(path) as stream:
                for line_number, row in enumerate(csv.DictReader(stream), start=2):
                    payload = {str(key): value for key, value in row.items() if key is not None}
                    records.append(_record(
                        self.dataset_id,
                        path,
                        line_number,
                        self._timestamp(payload),
                        payload,
                        self.version,
                    ))
                    if limit and len(records) >= limit:
                        break
        except (OSError, UnicodeError, csv.Error) as error:
            return AdapterResult(self.dataset_id, (), "error", (str(error),))
        return AdapterResult(self.dataset_id, tuple(records))


class LanlEventAdapter:
    dataset_id = "lanl"
    version = "lanl_typed_event_v1"
    _columns = {
        "auth": (
            "timestamp", "source_user", "destination_user", "source_computer",
            "destination_computer", "authentication_type", "logon_type",
            "authentication_orientation", "outcome",
        ),
        "proc": ("timestamp", "user", "computer", "process_name", "start_or_end"),
        "dns": ("timestamp", "source_computer", "computer_resolved"),
        "flows": (
            "timestamp", "duration", "source_computer", "source_port",
            "destination_computer", "destination_port", "protocol", "packet_count", "byte_count",
        ),
        "redteam": ("timestamp", "user", "source_computer", "destination_computer"),
    }

    @classmethod
    def _event_type(cls, path: Path) -> str:
        name = path.name.lower()
        return next((kind for kind in cls._columns if kind in name), "auth")

    def read(self, path: Path, limit: int = 0) -> AdapterResult:
        records: list[RawRecord] = []
        event_type = self._event_type(path)
        columns = self._columns[event_type]
        try:
            with _text_stream(path) as stream:
                for line_number, values in enumerate(csv.reader(stream), start=1):
                    if not values:
                        continue
                    payload = {
                        column: values[index] if index < len(values) else ""
                        for index, column in enumerate(columns)
                    }
                    payload["event_type"] = event_type
                    records.append(_record(
                        self.dataset_id,
                        path,
                        line_number,
                        payload.get("timestamp") or None,
                        payload,
                        self.version,
                    ))
                    if limit and len(records) >= limit:
                        break
        except (OSError, UnicodeError, csv.Error) as error:
            return AdapterResult(self.dataset_id, (), "error", (str(error),))
        return AdapterResult(self.dataset_id, tuple(records))


def adapter_for(dataset_id: str) -> SourceAdapter:
    normalized = dataset_id.strip().lower().replace("-", "_")
    if normalized in {"loghub", "loghub_2_0", "loghub2"}:
        return LogHubTextAdapter()
    if normalized in {"sandworm", "sandworm_flow", "sandworm_flows"}:
        return SandwormFlowAdapter()
    if normalized in {"lanl", "lanl_auth", "lanl_events"}:
        return LanlEventAdapter()
    raise ValueError(f"unsupported dataset adapter: {dataset_id}")
