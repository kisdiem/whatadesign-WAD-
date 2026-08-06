from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from src.common.schema import RawRecord


class SourceAdapter(ABC):
    adapter_version = "base-1"

    @abstractmethod
    def read(self) -> Iterable[RawRecord]:
        """Read source bytes only; labels and semantics are outside this boundary."""
        raise NotImplementedError
