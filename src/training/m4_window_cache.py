from __future__ import annotations

"""Planning primitives for provenance-preserving offline Qwen window caches.

The strict path is ``current``: every micro window ends relative to its current
event.  ``stride`` is an explicitly non-release precompute mode which snaps the
history anchor down to the configured stride; it is causal, but leaves at most
one stride of recency unrepresented.  Keeping this distinction in the cache
contract prevents an optimisation artifact being used as a strict result.
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from src.temporal.window_builder import WindowConfig


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class CachedMicroWindow:
    dataset_id: str
    start: datetime
    end: datetime
    current_record_id: str
    alignment: str

    @property
    def window_id(self) -> str:
        # The current ID deliberately participates only in exact mode.  In
        # stride mode identical causal windows can be shared safely.
        identity = "|".join((
            self.dataset_id,
            self.start.isoformat(),
            self.end.isoformat(),
            self.current_record_id if self.alignment == "current" else "shared",
            self.alignment,
        ))
        return "qwen-micro-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def plan_micro_windows(*, dataset_id: str, current_timestamp: str,
                       current_record_id: str, config: WindowConfig,
                       alignment: str = "current") -> list[CachedMicroWindow]:
    """Plan complete causal micro windows in chronological order.

    No event membership is accepted here: membership is applied later with
    ``start <= timestamp < end`` and always checks ``record_id != current``.
    """
    if alignment not in {"current", "stride"}:
        raise ValueError("alignment must be 'current' or 'stride'")
    current = parse_utc(current_timestamp)
    if alignment == "stride":
        epoch = current.timestamp()
        current = datetime.fromtimestamp(
            epoch - (epoch % config.stride_seconds), tz=timezone.utc
        )
    macro_start = current - timedelta(seconds=config.macro_seconds)
    micro = timedelta(seconds=config.micro_seconds)
    stride = timedelta(seconds=config.stride_seconds)
    windows: list[CachedMicroWindow] = []
    cursor = macro_start
    while cursor + micro <= current:
        windows.append(CachedMicroWindow(
            dataset_id=dataset_id,
            start=cursor,
            end=cursor + micro,
            current_record_id=current_record_id,
            alignment=alignment,
        ))
        cursor += stride
    return windows
