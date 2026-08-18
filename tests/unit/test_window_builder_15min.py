from src.temporal.window_builder import WindowBuilder, WindowConfig


def test_default_macro_window_is_15_minutes():
    builder = WindowBuilder()
    assert builder.config.macro_minutes == 15


def test_15_minute_macro_window_boundary():
    builder = WindowBuilder(WindowConfig(micro_minutes=5, macro_minutes=15))
    assert builder.assign(14 * 60 + 59)[1] == 0
    assert builder.assign(15 * 60)[1] == 1
