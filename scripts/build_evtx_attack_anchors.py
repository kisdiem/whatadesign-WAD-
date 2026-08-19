"""Build auditable ATT&CK anchors from EVTX content, not sample-path labels.

The EVTX sample collection is an external source-training corpus.  Each
exported anchor records its raw XML and the exact content rule that justified
the technique.  It contains no AIT labels and is not an evaluation artifact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from src.knowledge.attack_techniques import TechniqueSupervision


@dataclass(frozen=True)
class AnchorRule:
    rule_id: str
    technique_id: str
    predicate: Callable[[str], bool]
    confidence: float = 0.90


RULES = (
    AnchorRule("lsass_process_access", "T1003", lambda xml: "lsass" in xml and ("minidump" in xml or "sekurlsa" in xml or ("objecttype\">process" in xml and "accessmask" in xml))),
    AnchorRule("scheduled_task_create_or_delete", "T1053.005", lambda xml: (">4698<" in xml or ">4699<" in xml) and "taskname" in xml),
    AnchorRule("winrm_provider_process", "T1021.006", lambda xml: ("wsmprovhost" in xml or "winrshost" in xml) and (">1<" in xml or "processcreate" in xml)),
    AnchorRule("wmi_process_context", "T1047", lambda xml: ("wmic " in xml or "wmiprvse" in xml) and (">1<" in xml or "processcreate" in xml)),
    AnchorRule("service_created_7045", "T1543.003", lambda xml: ">7045<" in xml and "servicename" in xml and "imagepath" in xml),
    AnchorRule(
        "powershell_suspicious_scriptblock",
        "T1059.001",
        lambda xml: ("4104" in xml or "scriptblocktext" in xml)
        and "powershell" in xml
        and any(token in xml for token in ("invoke-mimikatz", "minidumpwritedump", "-encodedcommand", "frombase64string", "downloadstring", "invoke-expression")),
    ),
    AnchorRule(
        "rundll32_suspicious_proxy_execution",
        "T1218.011",
        lambda xml: "rundll32.exe" in xml
        and any(token in xml for token in ("javascript:", "url.dll,fileprotocolhandler", "advpack.dll,registerocx", "shdocvw.dll")),
    ),
    AnchorRule(
        "mshta_remote_or_script_execution",
        "T1218.005",
        lambda xml: "mshta.exe" in xml and any(token in xml for token in ("http://", "https://", "javascript:", "vbscript:")),
    ),
    AnchorRule(
        "certutil_remote_transfer",
        "T1105",
        lambda xml: "certutil.exe" in xml and any(token in xml for token in ("http://", "https://", "-urlcache", "-split")),
    ),
    AnchorRule(
        "registry_run_key_modified",
        "T1547.001",
        lambda xml: ("currentversion\\run" in xml or "currentversion/run" in xml)
        and ("eventid>13<" in xml or ">13<" in xml or "registry" in xml),
    ),
    AnchorRule(
        "local_account_created",
        "T1136.001",
        lambda xml: ">4720<" in xml and ("targetusername" in xml or "samaccountname" in xml),
    ),
    AnchorRule(
        "security_product_disable_command",
        "T1562.001",
        lambda xml: any(token in xml for token in ("set-mppreference", "disableantispyware", "disablebehavior", "net stop windefend", "sc stop windefend")),
    ),
    AnchorRule(
        "explicit_windows_command_shell",
        "T1059.003",
        lambda xml: ("cmd.exe" in xml or "cmd " in xml) and (" /c " in xml or " /k " in xml),
        confidence=0.80,
    ),
    AnchorRule(
        "system_information_discovery_command",
        "T1082",
        lambda xml: any(token in xml for token in ("systeminfo", "hostname", "get-computerinfo")),
        confidence=0.85,
    ),
    AnchorRule(
        "account_discovery_command",
        "T1087",
        lambda xml: any(token in xml for token in ("net user", "get-localuser", "get-aduser", "query user")),
        confidence=0.85,
    ),
    AnchorRule(
        "process_discovery_command",
        "T1057",
        lambda xml: any(token in xml for token in ("tasklist", "get-process", "wmic process")),
        confidence=0.85,
    ),
    AnchorRule(
        "remote_smb_service_execution_tool",
        "T1021.002",
        lambda xml: "psexec" in xml or "smbexec" in xml,
        confidence=0.80,
    ),
    AnchorRule(
        "windows_event_log_cleared",
        "T1070.001",
        lambda xml: ">1102<" in xml or "wevtutil cl " in xml or "clear-eventlog" in xml,
        confidence=0.90,
    ),
    AnchorRule(
        "remote_desktop_connection",
        "T1021.001",
        lambda xml: (
            ">1149<" in xml
            or (">4624<" in xml and ("logontype\">10<" in xml or "logontype\">10</" in xml))
        ) and "127.0.0.1" not in xml,
        confidence=0.78,
    ),
    AnchorRule(
        "web_service_spawned_command_interpreter",
        "T1505.003",
        lambda xml: any(token in xml for token in ("w3wp.exe", "httpd.exe", "nginx.exe"))
        and any(token in xml for token in ("cmd.exe", "powershell.exe")),
        confidence=0.80,
    ),
)


def matched_rules(xml: str) -> list[AnchorRule]:
    """Return all content-based matches for one lower-cased EVTX XML event."""
    return [rule for rule in RULES if rule.predicate(xml.lower())]


def stable_event_id(path: Path, record_index: int, xml: str) -> str:
    digest = hashlib.sha256(f"{path}|{record_index}|{xml}".encode("utf-8")).hexdigest()
    return f"evtx-anchor-{digest[:24]}"


def build_anchors(source_root: Path, event_output: Path, supervision_output: Path, max_per_tech: int = 50) -> Counter[str]:
    try:
        from Evtx.Evtx import Evtx  # type: ignore
    except ImportError as exc:
        raise RuntimeError("python-evtx is required; install it in the source-training environment") from exc

    event_output.parent.mkdir(parents=True, exist_ok=True)
    supervision_output.parent.mkdir(parents=True, exist_ok=True)
    counts: Counter[str] = Counter()
    seen: set[tuple[str, str]] = set()
    with event_output.open("w", encoding="utf-8") as events, supervision_output.open("w", encoding="utf-8") as supervision:
        for path in sorted(source_root.rglob("*.evtx")):
            try:
                with Evtx(str(path)) as log:
                    for record_index, record in enumerate(log.records(), start=1):
                        xml = record.xml()
                        matched = matched_rules(xml)
                        if not matched:
                            continue
                        record_id = stable_event_id(path, record_index, xml)
                        for rule in matched:
                            key = (record_id, rule.technique_id)
                            if key in seen or counts[rule.technique_id] >= max_per_tech:
                                continue
                            seen.add(key)
                            counts[rule.technique_id] += 1
                            events.write(json.dumps({
                                "record_id": record_id,
                                "dataset_id": "evtx_attack_samples",
                                "source_file": str(path),
                                "source_record_index": record_index,
                                "parser_version": "evtx_xml_v1",
                                "event_xml": xml,
                                "anchor_rule_id": rule.rule_id,
                            }, ensure_ascii=False, sort_keys=True) + "\n")
                            supervision.write(json.dumps(TechniqueSupervision(
                                record_id=record_id,
                                technique_id=rule.technique_id,
                                provenance=f"evtx_attack_samples/content_rule:{rule.rule_id}",
                                confidence=rule.confidence,
                                reviewer="codex-audited-rule-v1",
                                notes="External source-training anchor; content rule passed, not inferred from filename or AIT label.",
                            ).to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
            except Exception as exc:
                print(json.dumps({"skipped_file": str(path), "reason": str(exc)}))
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--event-output", type=Path, required=True)
    parser.add_argument("--supervision-output", type=Path, required=True)
    parser.add_argument("--max-per-tech", type=int, default=50)
    args = parser.parse_args()
    counts = build_anchors(args.source_root, args.event_output, args.supervision_output, args.max_per_tech)
    print(json.dumps({"total": sum(counts.values()), "by_technique": dict(sorted(counts.items()))}, sort_keys=True))


if __name__ == "__main__":
    main()
