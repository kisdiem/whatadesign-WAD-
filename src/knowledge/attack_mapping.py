"""Generate auditable ATT&CK candidates from normalized event facts.

This module intentionally produces candidates, not attack ground truth.  It
does not accept dataset split or label fields and preserves an explicit unknown
result when the observed facts do not justify a mapping.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from src.common.schema import EventFrame


FORBIDDEN_KEYS = frozenset({
    "target_label", "attack_label", "anomaly_label", "is_attack", "label",
    "ground_truth", "split", "scenario_truth", "post_hoc_score",
})
MAPPING_VERSION = "attack-candidate-rules-v1"


@dataclass(frozen=True)
class AttackCandidate:
    technique_id: str
    tactic_id: str
    confidence: float
    mapping_source: str
    evidence: dict[str, Any]
    disposition: str = "candidate"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _contains_forbidden(value: Any) -> str | None:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_KEYS:
                return normalized
            found = _contains_forbidden(nested)
            if found:
                return found
    elif isinstance(value, list):
        for nested in value:
            found = _contains_forbidden(nested)
            if found:
                return found
    return None


def _fact_text(frame: EventFrame, observables: dict[str, Any] | None = None) -> str:
    """Use only normalized event facts and descriptive metadata."""
    payload = {
        "record_kind": frame.record_kind,
        "relation_type": frame.relation_type,
        "action_family": frame.action_family,
        "action_leaf": frame.action_leaf,
        "outcome": frame.outcome,
        "roles": frame.roles,
        "entity_mentions": frame.entity_mentions,
        "key_attributes": frame.key_attributes,
        "actor": frame.actor,
        "object": frame.object,
        "attributes": frame.attributes,
        "observables": observables or {},
    }
    forbidden = _contains_forbidden(payload)
    if forbidden:
        raise ValueError(f"ATT&CK mapping refuses forbidden field: {forbidden}")
    return " ".join(str(value).lower() for value in payload.values())


def map_eventframe(frame: EventFrame, observables: dict[str, Any] | None = None, policy: str = "balanced") -> list[AttackCandidate]:
    """Return conservative ATT&CK technique candidates for one event."""
    text = _fact_text(frame, observables)
    if policy not in {"balanced", "balanced_plus", "recall_first"}:
        raise ValueError(f"unsupported ATT&CK mapping policy: {policy}")
    action = frame.action_family.lower()
    candidates: list[AttackCandidate] = []

    if "powershell" in text and any(token in text for token in ("-enc", "encodedcommand", "encoded command")):
        candidates.append(AttackCandidate(
            "T1059.001", "execution", 0.94, "structured_rule",
            {"required_terms": ["powershell", "encoded_command"], "action_family": action},
        ))
    elif "powershell" in text:
        candidates.append(AttackCandidate(
            "T1059.001", "execution", 0.76, "structured_rule",
            {"required_terms": ["powershell"], "action_family": action},
        ))

    if "lsass" in text and any(token in text for token in ("read", "access", "openprocess", "memory")):
        candidates.append(AttackCandidate(
            "T1003", "credential-access", 0.90, "structured_rule",
            {"required_terms": ["lsass", "process_memory_access"], "action_family": action},
        ))

    if any(token in text for token in ("schtasks", "scheduled task", "task scheduler")) and action in {"create", "execute", "start"}:
        candidates.append(AttackCandidate(
            "T1053", "execution", 0.84, "structured_rule",
            {"required_terms": ["scheduled_task"], "action_family": action},
        ))

    if any(token in text for token in ("wget", "curl", "bitsadmin", "invoke-webrequest")) and action in {"execute", "connect", "create", "write"}:
        candidates.append(AttackCandidate(
            "T1105", "command-and-control", 0.72, "structured_rule",
            {"required_terms": ["transfer_utility"], "action_family": action},
        ))

    if any(token in text for token in ("nmap", "network scan", "port scan", "et scan")):
        candidates.append(AttackCandidate(
            "T1595", "reconnaissance", 0.78, "structured_rule",
            {"required_terms": ["network_or_port_scan"], "action_family": action},
        ))

    if any(token in text for token in ("brute force", "bruteforce", "multiple failed login")):
        candidates.append(AttackCandidate(
            "T1110", "credential-access", 0.76, "structured_rule",
            {"required_terms": ["brute_force_indicator"], "action_family": action},
        ))

    if "webshell" in text:
        candidates.append(AttackCandidate(
            "T1505.003", "persistence", 0.74, "structured_rule",
            {"required_terms": ["webshell"], "action_family": action},
        ))

    # A web connection alone is ambiguous, so this stays a low-confidence
    # hypothesis and cannot independently create an M5 link.
    if frame.record_kind == "network" and frame.action_family == "connect" and any(token in text for token in ("http", "https")):
        candidates.append(AttackCandidate(
            "T1071.001", "command-and-control", 0.35, "structured_rule",
            {"required_terms": ["web_protocol", "network_connect"], "ambiguity": "benign_web_traffic_possible"},
        ))

    if policy in {"balanced_plus", "recall_first"}:
        # These additions still require explicit, behavior-bearing phrases.
        # They are deliberately narrower than the recall-first hypotheses.
        if any(token in text for token in ("sshd accepted", "rdp logon", "winrm session")):
            candidates.append(AttackCandidate(
                "T1021", "lateral-movement", 0.58, "structured_rule",
                {"required_terms": ["specific_remote_service_login"], "action_family": action},
            ))
        if any(token in text for token in ("sql injection", "exploit attempt", "exploit public-facing")):
            candidates.append(AttackCandidate(
                "T1190", "initial-access", 0.56, "structured_rule",
                {"required_terms": ["exploit_indicator"], "action_family": action},
            ))
        if any(token in text for token in ("useradd", "adduser", "net user")) and action in {"execute", "create"}:
            candidates.append(AttackCandidate(
                "T1136", "persistence", 0.62, "structured_rule",
                {"required_terms": ["account_creation_utility"], "action_family": action},
            ))

    if policy == "recall_first":
        # These hypotheses intentionally favor recall.  They are review-only:
        # downstream M5 must still require entity/flow evidence before linking.
        if any(token in text for token in ("cmd.exe", "command prompt", "bash", "/bin/sh", "cscript", "wscript")) and not any(c.technique_id.startswith("T1059") for c in candidates):
            candidates.append(AttackCandidate(
                "T1059", "execution", 0.38, "recall_rule",
                {"indicator": "command_interpreter_term", "review_required": True}, "review_only",
            ))
        if any(token in text for token in ("ssh", "rdp", "remote desktop", "smb", "winrm")):
            candidates.append(AttackCandidate(
                "T1021", "lateral-movement", 0.30, "recall_rule",
                {"indicator": "remote_service_term", "review_required": True}, "review_only",
            ))
        if any(token in text for token in ("dns query", "dns request", "dns lookup")):
            candidates.append(AttackCandidate(
                "T1071.004", "command-and-control", 0.18, "recall_rule",
                {"indicator": "dns_traffic_term", "ambiguity": "ordinary_dns_is_common", "review_required": True}, "review_only",
            ))
        if any(token in text for token in ("failed password", "failed login", "authentication failure", "invalid user")) and not any(c.technique_id == "T1110" for c in candidates):
            candidates.append(AttackCandidate(
                "T1110", "credential-access", 0.28, "recall_rule",
                {"indicator": "authentication_failure_term", "review_required": True}, "review_only",
            ))

    return candidates


def mapping_record(frame: EventFrame, observables: dict[str, Any] | None = None, policy: str = "balanced") -> dict[str, Any]:
    candidates = map_eventframe(frame, observables, policy)
    return {
        "schema_version": "attack-candidate-v1",
        "mapping_version": MAPPING_VERSION,
        "policy": policy,
        "record_id": frame.record_id,
        "dataset_id": frame.dataset_id,
        "timestamp": frame.timestamp,
        "candidates": [candidate.to_dict() for candidate in candidates],
        "status": "mapped" if candidates else "unknown",
    }
