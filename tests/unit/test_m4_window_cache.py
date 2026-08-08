from datetime import datetime, timezone

from src.temporal.window_builder import WindowConfig
from src.training.m4_window_cache import plan_micro_windows


def test_current_alignment_is_exact_and_has_eleven_windows():
    windows = plan_micro_windows(
        dataset_id="source", current_timestamp="2025-01-01T00:30:17+00:00",
        current_record_id="current", config=WindowConfig(), alignment="current",
    )
    assert len(windows) == 11
    assert windows[0].start == datetime(2025, 1, 1, tzinfo=timezone.utc, minute=0, second=17)
    assert windows[-1].end == datetime(2025, 1, 1, tzinfo=timezone.utc, minute=30, second=17)


def test_stride_alignment_is_explicitly_distinct_and_causal():
    windows = plan_micro_windows(
        dataset_id="source", current_timestamp="2025-01-01T00:30:17+00:00",
        current_record_id="current", config=WindowConfig(), alignment="stride",
    )
    assert len(windows) == 11
    assert windows[-1].end == datetime(2025, 1, 1, tzinfo=timezone.utc, minute=30)
    assert windows[-1].end < datetime(2025, 1, 1, tzinfo=timezone.utc, minute=30, second=17)
    assert windows[0].window_id == plan_micro_windows(
        dataset_id="source", current_timestamp="2025-01-01T00:30:42+00:00",
        current_record_id="other", config=WindowConfig(), alignment="stride",
    )[0].window_id
