from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

@dataclass(frozen=True)
class WindowConfig:
    micro_seconds: int = 300
    stride_seconds: int = 150
    macro_seconds: int = 1800
    def __post_init__(self):
        if not (self.macro_seconds >= self.micro_seconds > 0 and 0 < self.stride_seconds <= self.micro_seconds): raise ValueError('invalid temporal window configuration')

@dataclass(frozen=True)
class MicroWindow:
    window_id: str; start: datetime; end: datetime; record_ids: tuple[str,...]; event_indices: tuple[int,...]; valid_mask: tuple[bool,...]

class WindowBuilder:
    def __init__(self, config: WindowConfig|None=None): self.config=config or WindowConfig()
    def assign(self,timestamp_seconds:float)->tuple[int,int]: return (int(timestamp_seconds//self.config.micro_seconds),int(timestamp_seconds//self.config.macro_seconds))
    def build_micro_windows(self,events,current_timestamp,current_record_id):
        now=self._time(current_timestamp); history=[]
        for i,event in enumerate(events):
            stamp=self._time(event.timestamp)
            if event.record_id!=current_record_id and now-timedelta(seconds=self.config.macro_seconds)<=stamp<now: history.append((stamp,i,event))
        history.sort(key=lambda row:(row[0],row[2].record_id)); earliest=history[0][0] if history else now
        start=max(now-timedelta(seconds=self.config.macro_seconds),earliest); result=[]; cursor=start; n=0
        # A micro window is always a complete [start, end) 5-minute interval.
        # For full history this gives floor((1800-300)/150)+1 == 11, never a
        # short tail window that would alter the intended overlap semantics.
        while cursor + timedelta(seconds=self.config.micro_seconds) <= now:
            end=cursor+timedelta(seconds=self.config.micro_seconds); rows=[row for row in history if cursor<=row[0]<end]
            result.append(MicroWindow(f'micro:{current_record_id}:{n}',cursor,end,tuple(r[2].record_id for r in rows),tuple(r[1] for r in rows),tuple(True for _ in rows))); cursor+=timedelta(seconds=self.config.stride_seconds); n+=1
        return result
    @staticmethod
    def _time(value):
        if isinstance(value,datetime): return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        parsed=datetime.fromisoformat(str(value).replace('Z','+00:00')); return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
