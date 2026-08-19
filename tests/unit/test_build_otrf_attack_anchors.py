from scripts.build_otrf_attack_anchors import is_eventlog_service_disabled


def test_eventlog_disable_requires_specific_service_start_change():
    assert is_eventlog_service_disabled({"EventID": 4688, "Message": "REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog /t REG_DWORD /v Start /d 4"})
    assert is_eventlog_service_disabled({"EventID": 13, "TargetObject": "HKLM\\System\\CurrentControlSet\\Services\\EventLog\\Start", "Details": "DWORD (0x00000004)"})
    assert not is_eventlog_service_disabled({"EventID": 13, "TargetObject": "HKLM\\System\\CurrentControlSet\\Services\\EventLog\\FlushTimer", "Details": "DWORD (0x00000001)"})
