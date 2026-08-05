from src.training.leakage_audit import audit_records
from src.training.splits import source_held_out


def test_source_held_out_never_puts_held_source_in_train():
    rows = [{"record_id": f"r{i}", "source_dataset": source} for i, source in enumerate(["evtx", "evtx", "sandworm", "ctu"])]
    split = source_held_out(rows, "sandworm")
    assert all(row["source_dataset"] != "sandworm" for row in split.train + split.validation)
    assert all(row["source_dataset"] == "sandworm" for row in split.test)


def test_leakage_audit_rejects_target_and_duplicates():
    result = audit_records([
        {"record_id": "r", "source_dataset": "evtx"},
        {"record_id": "r", "source_dataset": "ait_ads"},
    ])
    assert not result.passed
    assert any("duplicate" in item for item in result.findings)
    assert any("target_access" in item for item in result.findings)
