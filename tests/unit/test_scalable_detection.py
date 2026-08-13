from pathlib import Path

from src.detection.engine import ScalableDetectionEngine
from src.detection.sources import SourceDescriptor, discover_sources, iter_source
from src.detection.unsupervised import CountMinSketch, StreamingFrequencyBaseline


def test_count_min_sketch_has_fixed_memory() -> None:
    sketch = CountMinSketch(width=128, depth=4)
    before = sketch.bytes_allocated
    for index in range(10_000):
        sketch.add(f"value-{index}")
    assert sketch.bytes_allocated == before == 128 * 4 * 4
    assert sketch.estimate("value-1") >= 1


def test_discovery_excludes_labels_and_binary_payloads(tmp_path: Path) -> None:
    gather = tmp_path / "gather"
    labels = tmp_path / "labels"
    gather.mkdir(); labels.mkdir()
    (gather / "eve.json").write_text('{"timestamp":"2026-01-01T00:00:00Z","event_type":"dns","src_ip":"10.0.0.1","dns":{"rrname":"a.example"}}\n', encoding="utf-8")
    (gather / "traffic.pcap").write_bytes(b"binary")
    (labels / "attack.log").write_text("secret labels", encoding="utf-8")
    sources, exclusions = discover_sources([tmp_path])
    assert [source.kind for source in sources] == ["suricata_jsonl"]
    assert any("pcap" in path for path in exclusions)
    assert any("labels-directory" in path for path in exclusions)
    assert all("labels" not in {part.lower() for part in Path(source.path).relative_to(tmp_path).parts} for source in sources)


def test_scalable_engine_keeps_bounded_state(tmp_path: Path) -> None:
    root = tmp_path / "dataset" / "gather"
    root.mkdir(parents=True)
    source = root / "eve.json"
    source.write_text("\n".join(
        f'{{"timestamp":"2026-01-01T00:{index:02d}:00Z","event_type":"dns","src_ip":"10.0.0.{index}","dns":{{"rrname":"value{index}.example"}}}}'
        for index in range(10)
    ) + "\n", encoding="utf-8")
    output = tmp_path / "output"
    result = ScalableDetectionEngine().run_roots([root.parent], output, top_k=3, sketch_width=128)
    assert result.input_count == 10
    assert result.manifest["labels_accessed"] is False
    assert result.manifest["memory_contract"]["max_retained_candidates"] == 3
    assert result.manifest["memory_contract"]["state_grows_with_input"] is False
    assert result.manifest["memory_contract"]["count_min_sketch_bytes"] > 0

    online = ScalableDetectionEngine().run_roots_online([root.parent], tmp_path / "online", top_k=3, sketch_width=128)
    assert online.manifest["passes"] == 1
    assert online.manifest["execution_mode"] == "bounded_memory_online_single_pass"
    assert online.manifest["labels_accessed"] is False


def test_investigations_split_independent_hosts_and_long_gaps() -> None:
    def window(identifier: str, start: str, entity: str) -> dict:
        return {
            "id": identifier, "start": start, "end": start, "entities": [entity, "cmd.exe"],
            "severity": "high", "weak_supervision": {"tactics": ["Execution"]},
        }

    cases = ScalableDetectionEngine._investigations([
        window("WIN-1", "2026-01-01T00:00:00+00:00", "HOST-A"),
        window("WIN-2", "2026-01-03T00:00:00+00:00", "HOST-A"),
        window("WIN-3", "2026-01-03T01:00:00+00:00", "HOST-B"),
        window("WIN-4", "2026-01-20T00:00:00+00:00", "HOST-A"),
    ])
    assert [case["windowIds"] for case in cases] == [["WIN-1", "WIN-2"], ["WIN-3"], ["WIN-4"]]
    assert all(case["labels_accessed"] is False for case in cases)


def test_evtx_discovery_uses_only_unlabelled_csv_projection(tmp_path: Path) -> None:
    (tmp_path / "evtx_data.csv").write_text("SystemTime,EVTX_Tactic,EventID\n2026-01-01T00:00:00Z,Execution,1\n", encoding="utf-8")
    metadata = tmp_path / "EVTX_ATT&CK_Metadata"
    metadata.mkdir()
    (metadata / "mapping.json").write_text('{"label":"Execution"}', encoding="utf-8")
    (tmp_path / "sample.evtx").write_bytes(b"binary")
    sources, exclusions = discover_sources([tmp_path])
    assert [(source.kind, Path(source.path).name) for source in sources] == [("evtx_csv", "evtx_data.csv")]
    assert any("metadata" in path for path in exclusions)
