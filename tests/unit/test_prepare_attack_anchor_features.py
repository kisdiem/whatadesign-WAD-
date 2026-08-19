from scripts.prepare_attack_anchor_features import eventframe_from_evtx_anchor, serialize_eventframe


def test_evtx_serialization_contains_event_facts_but_no_anchor_label():
    frame = eventframe_from_evtx_anchor({
        "record_id": "record-1",
        "dataset_id": "evtx",
        "event_xml": "<Event><System><Provider Name='Sysmon'/><EventID>1</EventID><Computer>host</Computer></System><EventData><Data Name='Image'>cmd.exe</Data></EventData></Event>",
    })
    text = serialize_eventframe(frame)
    assert "Sysmon" in text
    assert "cmd.exe" in text
    assert "technique" not in text.lower()


def test_otrf_json_event_uses_facts_without_supervision_fields():
    frame = eventframe_from_evtx_anchor({
        "record_id": "otrf-1", "dataset_id": "otrf", "raw_format": "jsonl_windows_event",
        "raw_payload": {"EventID": 4688, "Message": "REG ADD HKLM\\Services\\EventLog /v Start /d 4"},
    })
    assert "4688" in serialize_eventframe(frame)
