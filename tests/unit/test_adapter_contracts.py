from pathlib import Path

from src.data.adapters import LogHubTextAdapter, SandwormFlowAdapter, adapter_for


def test_loghub_adapter_preserves_source_identity(tmp_path: Path):
    path = tmp_path / "a.log"
    path.write_text("one\ntwo\n", encoding="utf-8")
    result = LogHubTextAdapter().read(path)
    assert result.status == "ok"
    assert [row.source_line for row in result.records] == [1, 2]
    assert all(row.dataset_id == "loghub_2_0" for row in result.records)


def test_sandworm_adapter_reads_csv_payload(tmp_path: Path):
    path = tmp_path / "flow.csv"
    path.write_text("timestamp,src,dst\n2025-01-01T00:00:00Z,a,b\n", encoding="utf-8")
    result = SandwormFlowAdapter().read(path)
    assert result.records[0].raw_payload["src"] == "a"
    assert result.records[0].raw_timestamp.startswith("2025-")


def test_unknown_adapter_is_rejected():
    try:
        adapter_for("unknown")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown dataset must not silently use another adapter")
