from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from .schema import LogEvent


@dataclass(frozen=True)
class WeakRule:
    rule_id: str
    pattern: str
    weight: float
    tactic: str
    reason: str
    source_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class WeakVote:
    score: float
    confidence: float
    rules: tuple[dict[str, object], ...]
    tactics: tuple[str, ...]


DEFAULT_RULES = (
    WeakRule("WS-PS-ENCODED", r"powershell.*(?:-enc|-encodedcommand|frombase64string)", 0.95, "Execution", "编码 PowerShell 命令"),
    WeakRule("WS-LOLBIN", r"(?:certutil|bitsadmin|rundll32|regsvr32).*(?:http|download|urlcache)", 0.88, "Execution", "系统工具下载或代理执行"),
    WeakRule("WS-WEBSHELL", r"(?:cmd=|shell\.php|/bin/sh|whoami).*(?:http|waf|uri|status)", 0.92, "Persistence", "疑似 WebShell 命令执行"),
    WeakRule("WS-CREDENTIAL-DUMP", r"(?:mimikatz|sekurlsa|lsass.*(?:dump|access)|procdump.*lsass)", 0.98, "Credential Access", "凭据转储行为"),
    WeakRule("WS-DNS-TUNNEL", r"(?:query|qname|dns_query)(?:\"|')?\s*[=:]\s*(?:\"|')?[a-z0-9*+/_-]{24,}\.[a-z0-9*+/_-]{8,}", 0.86, "Command and Control", "高熵长子域查询"),
    WeakRule("WS-SURICATA-HIGH", r"(?:signature|description)(?:\"|')?\s*[=:]\s*(?:\"|')?.*(?:exploit|trojan|malware|command and control|credential|webshell)", 0.82, "Initial Access", "高风险网络检测签名"),
    WeakRule("WS-BRUTE-FORCE", r"(?:failed|failure|invalid).*(?:login|logon|password).*(?:count|attempts?)[=: ]+(?:[6-9]|[1-9][0-9]+)", 0.78, "Credential Access", "短时认证失败聚集"),
    WeakRule("WS-SENSITIVE-EXFIL", r"(?:shadow|passwd|sensitive|secret|finance).*(?:archive|zip|upload|egress|external)", 0.90, "Exfiltration", "敏感文件归档或外传"),
)


class WeakSupervisor:
    """Auditable label-function voting; it never consumes ground-truth labels."""

    def __init__(self, rules: tuple[WeakRule, ...] = DEFAULT_RULES) -> None:
        self.rules = rules
        self._compiled = [(rule, re.compile(rule.pattern, re.I)) for rule in rules]

    def vote(self, event: LogEvent) -> WeakVote:
        text = f"{event.source_type} {event.message}"
        matched: list[WeakRule] = []
        for rule, pattern in self._compiled:
            if rule.source_types and event.source_type.lower() not in {x.lower() for x in rule.source_types}:
                continue
            if pattern.search(text):
                matched.append(rule)
        score = 1.0
        for rule in matched:
            score *= 1.0 - rule.weight
        score = 1.0 - score if matched else 0.0
        return WeakVote(
            score=score,
            confidence=min(0.99, 0.55 + 0.12 * len(matched)) if matched else 0.0,
            rules=tuple(asdict(rule) for rule in matched),
            tactics=tuple(dict.fromkeys(rule.tactic for rule in matched)),
        )

    def manifest(self) -> list[dict[str, object]]:
        return [asdict(rule) for rule in self.rules]
