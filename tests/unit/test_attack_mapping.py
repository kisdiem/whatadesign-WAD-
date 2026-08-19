from src.common.schema import EventFrame
from src.knowledge.attack_mapping import map_eventframe, mapping_record


def test_powershell_encoded_command_maps_to_execution_candidate():
    frame = EventFrame(record_id="evt-1", dataset_id="source", action_family="execute", attributes={"command_line": "powershell -enc AAAA"})
    candidate = map_eventframe(frame)[0]
    assert candidate.technique_id == "T1059.001"
    assert candidate.tactic_id == "execution"


def test_unknown_event_is_preserved_as_unknown():
    frame = EventFrame(record_id="evt-2", dataset_id="source", action_family="unknown")
    assert mapping_record(frame)["status"] == "unknown"


def test_ids_scan_message_maps_without_using_labels():
    frame = EventFrame(record_id="evt-scan", dataset_id="source", action_family="observe")
    candidate = map_eventframe(frame, {"message": "ET SCAN Nmap User-Agent Detected"})[0]
    assert candidate.technique_id == "T1595"


def test_recall_policy_marks_ambiguous_dns_as_review_only():
    frame = EventFrame(record_id="evt-dns", dataset_id="source", action_family="observe")
    candidate = map_eventframe(frame, {"message": "Observed DNS Query to .biz TLD"}, policy="recall_first")[0]
    assert candidate.technique_id == "T1071.004"
    assert candidate.disposition == "review_only"


def test_balanced_plus_requires_specific_remote_login_phrase():
    frame = EventFrame(record_id="evt-rdp", dataset_id="source", action_family="authenticate")
    candidates = map_eventframe(frame, {"message": "sshd Accepted password for admin"}, policy="balanced_plus")
    assert candidates[0].technique_id == "T1021"
    assert candidates[0].disposition == "candidate"


def test_mapping_rejects_labels_in_event_metadata():
    frame = EventFrame(record_id="evt-3", dataset_id="source", attributes={"attack_label": 1})
    try:
        mapping_record(frame)
    except ValueError as exc:
        assert "forbidden" in str(exc)
    else:
        raise AssertionError("label-bearing EventFrame must be rejected")
