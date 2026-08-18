"""M6 校准评分公共函数。

供 scan_sources.py（四源统计）与 project_m6.py（Short/Long 重投影）共用。
规则与 agent_service/ingestion.py 保持同一套口径：弱监督信号、实体提取、
模板指纹与 M6 融合公式均与上传链路一致，避免演示与实时两套算法不一致。
标签（labels/、labels.csv、EVTX_Tactic 等）绝不进入任何评分输入。
"""
from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_RE = re.compile(r"(?:(?:user(?:name)?|login|uid|SubjectUserName|TargetUserName)[=: ]+|account[=:]+)['\"]?([A-Za-z0-9_.@\\-]+)", re.I)
HOST_RE = re.compile(r"(?:host(?:name)?|computer|WorkstationName|SourceHostname|DestinationHostname)[=: ]+['\"]?([A-Za-z0-9_.-]+)", re.I)
PROCESS_RE = re.compile(r"(?:process|image|CommandLine|NewProcessName|ParentProcessName|CallerProcessName)[=: ]+['\"]?([^,;\s]+)", re.I)
MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
NUM_RE = re.compile(r"\b\d+\b")
ENTITY_NOISE = {"pid", "uid", "gid", "none", "null", "n/a", "na", "example", "unknown", "user", "username", "account", "host", "hostname", "process", "image", "command", "-", "?", "-"}


def _clean_entity(value: str) -> str | None:
    cleaned = str(value).strip().strip('"').strip("'").strip("\\")
    if not cleaned:
        return None
    if cleaned.isdigit():
        return None
    if cleaned.lower() in ENTITY_NOISE:
        return None
    if len(cleaned) > 64:
        return None
    return cleaned


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def template_fingerprint(text: str) -> str:
    """去变量后的日志结构指纹，用于模板稀有度统计（替代 Drain 的轻量近似）。

    保留标点与字段名，替换时间/IP/MAC/数字/短 token 为占位符。
    """
    value = str(text)
    value = TIME_RE.sub("<time>", value)
    value = IP_RE.sub("<ip>", value)
    value = MAC_RE.sub("<mac>", value)
    value = NUM_RE.sub("<num>", value)
    tokens = re.findall(r"[\w.-]+|[^\w\s]", value, re.UNICODE)
    fingerprint: list[str] = []
    for token in tokens:
        if len(token) <= 2 or re.fullmatch(r"<[a-z]+>", token):
            fingerprint.append("<tok>")
        else:
            fingerprint.append(token.lower())
    return " ".join(fingerprint)[:300]


def extract_entities(text: str, payload: dict[str, Any] | None = None) -> dict[str, list[str]]:
    """从日志文本 + JSON 字段提取实体，返回 {type: [value]}，保持出现顺序去重。"""
    raw = str(text or "")
    output: dict[str, list[str]] = {
        "ip": list(dict.fromkeys(IP_RE.findall(raw))),
        "user": list(dict.fromkeys(USER_RE.findall(raw))),
        "host": list(dict.fromkeys(HOST_RE.findall(raw))),
        "process": list(dict.fromkeys(PROCESS_RE.findall(raw))),
    }
    if isinstance(payload, dict):
        lowered = {str(key).lower(): value for key, value in payload.items()}
        aliases = {
            "ip": ("ip", "ipaddress", "src_ip", "dst_ip", "source_ip", "destination_ip", "dest_ip", "sourceaddress", "destinationip", "clientip", "remote_ip"),
            "user": ("user", "username", "account", "actor", "subjectusername", "targetusername", "samaccountname", "userprincipalname", "userid"),
            "host": ("host", "hostname", "computer", "device", "workstationname", "sourcehostname", "destinationhostname", "agent"),
            "process": ("process", "processname", "image", "command", "commandline", "newprocessname", "parentimagename", "callerprocessname", "processpath", "imagepath"),
        }
        for entity_type, keys in aliases.items():
            for key in keys:
                value = lowered.get(key)
                if value in (None, "", "-"):
                    continue
                if isinstance(value, (str, int)):
                    output[entity_type].append(str(value).strip())
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, (str, int)) and str(item).strip() not in ("", "-"):
                            output[entity_type].append(str(item).strip())
    for entity_type in tuple(output):
        cleaned: list[str] = []
        for value in output[entity_type]:
            candidate = _clean_entity(value)
            if candidate is None:
                continue
            if candidate.startswith("S-1-") or candidate.startswith("{"):
                continue  # SID / GUID 不计入用户实体
            cleaned.append(candidate)
        output[entity_type] = list(dict.fromkeys(cleaned))
    return {key: values for key, values in output.items() if values}


def weak_supervision(text: str) -> tuple[float, list[str]]:
    """弱监督规则信号，与 agent_service/ingestion.py 的 _weak_supervision 保持一致。"""
    lowered = str(text or "").lower()
    hits: list[tuple[float, str]] = []
    rules = (
        (0.88, ("mimikatz", "credential dump", "lsass"), "凭据访问高风险关键词"),
        (0.82, ("powershell -enc", "encodedcommand", "rundll32", "certutil", "scriptblocktext"), "可疑脚本或系统工具执行"),
        (0.78, ("useradd", "new user", "add user", "net user", "samaccountname"), "账户创建或组成员变更"),
        (0.72, ("failed password", "authentication failure", "login failed", "4625"), "认证失败事件"),
        (0.68, ("sudo", "session opened for user root", "privilege", "elevatedtoken"), "权限上下文变化"),
        (0.64, ("denied", "blocked", "waf", "malicious", "alert"), "安全设备拒绝或恶意标记"),
        (0.60, ("dns", "connect", "outbound", "external", "network"), "网络连接需要结合上下文核查"),
    )
    for score, tokens, reason in rules:
        if any(token in lowered for token in tokens):
            hits.append((score, reason))
    if not hits:
        return 0.08, ["未命中弱监督高风险规则"]
    return max(score for score, _ in hits), list(dict.fromkeys(reason for _, reason in hits))


def source_kind_from_name(path: str, name: str) -> str:
    """按文件名/路径推断日志源类型，用于源多样性统计。"""
    lowered = str(path).lower()
    if "eve.json" in name.lower():
        return "suricata"
    if name.lower().startswith("auth.log") or "auth" in lowered:
        return "auth"
    if "dnsmasq" in name.lower():
        return "dns"
    if "openvpn" in name.lower():
        return "vpn"
    if name.lower().startswith("kern.log") or "kern" in lowered:
        return "kernel"
    if "audit" in lowered or name.lower().startswith("audit.log"):
        return "audit"
    if "mail" in name.lower() or "exim" in lowered:
        return "mail"
    if "waf" in lowered or "apache" in lowered or "nginx" in lowered or "access" in name.lower():
        return "web"
    if "syslog" in name.lower():
        return "syslog"
    if "message" in name.lower():
        return "syslog"
    if "evtx" in name.lower() or name.lower().endswith(".csv"):
        return "evtx"
    if "aminer" in name.lower():
        return "aminer"
    if "wazuh" in name.lower():
        return "wazuh"
    if "suricata" in lowered:
        return "suricata"
    if "sm.log" in name.lower() or "attacks.log" in name.lower() or "dnsteal" in name.lower():
        return "scenario"
    return "other"


def entity_key(entity_type: str, value: str) -> str:
    return f"{entity_type}:{value}"


def serialize_counter(counter: Counter[str], limit: int = 50000) -> dict[str, int]:
    """Counter → 有序 dict（频率降序），限制条目数控制产物体积。"""
    ordered = counter.most_common(limit)
    return {key: count for key, count in ordered}


def json_dump(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
