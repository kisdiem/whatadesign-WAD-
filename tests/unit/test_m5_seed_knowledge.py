import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
KNOWLEDGE_PATH = ROOT / "knowledge" / "m5_seed_knowledge.jsonl"
STAGE_PATH = ROOT / "knowledge" / "m5_seed_stage_schema.json"


def _records():
    return [json.loads(line) for line in KNOWLEDGE_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_seed_knowledge_is_small_unique_and_well_formed():
    rows = _records()
    assert 10 <= len(rows) <= 32
    assert len({row["knowledge_id"] for row in rows}) == len(rows)
    assert len({row["attack_id"] for row in rows}) == len(rows)

    required = {
        "knowledge_id",
        "source",
        "source_version",
        "attack_id",
        "name",
        "primary_tactic",
        "positions",
        "progress",
        "text",
        "log_clues",
        "source_url",
    }
    for row in rows:
        assert required <= row.keys()
        assert row["source"] == "MITRE_ATT&CK"
        assert row["attack_id"].startswith("T")
        assert row["text"].strip()
        assert row["log_clues"]
        assert all(0 <= int(position) < 10 for position in row["positions"])
        assert 0.0 <= float(row["progress"]) <= 1.0
        assert row["source_url"].startswith("https://attack.mitre.org/techniques/")
        assert "embedding" not in row


def test_seed_knowledge_covers_the_main_coarse_chain():
    positions = {int(position) for row in _records() for position in row["positions"]}
    assert positions == set(range(10))


def test_stage_schema_matches_model_position_count():
    schema = json.loads(STAGE_PATH.read_text(encoding="utf-8"))
    positions = schema["positions"]
    assert len(positions) == 10
    assert [row["index"] for row in positions] == list(range(10))
    assert all(0.0 <= float(row["progress_prior"]) <= 1.0 for row in positions)
