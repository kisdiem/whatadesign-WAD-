from __future__ import annotations

import json
import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

KNOWLEDGE_VERSION = "wad-kb-2026.08-v1"
_KNOWLEDGE_PATH = Path(__file__).with_name("project_knowledge.json")
_ASCII_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.:/+-]*", re.IGNORECASE)
_CJK_RUN = re.compile(r"[\u3400-\u9fff]+")
_STOPWORDS = {"什么", "怎么", "如何", "一下", "这个", "我们", "项目", "系统", "现在", "可以", "为什么"}


def _tokens(value: str) -> list[str]:
    text = value.lower()
    output = _ASCII_TOKEN.findall(text)
    for run in _CJK_RUN.findall(text):
        output.extend(char for char in run if char.strip())
        output.extend(run[index:index + 2] for index in range(max(0, len(run) - 1)))
        output.extend(run[index:index + 3] for index in range(max(0, len(run) - 2)))
    return [token for token in output if token not in _STOPWORDS]


@lru_cache(maxsize=1)
def load_project_knowledge() -> tuple[dict[str, Any], ...]:
    with _KNOWLEDGE_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        raise ValueError("project_knowledge.json must contain a list")
    return tuple(item for item in payload if isinstance(item, dict))


def _document_id(document: dict[str, Any]) -> str:
    return str(document.get("document_id") or document.get("id") or "")


def merge_knowledge_documents(external: Iterable[dict[str, Any]] = ()) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {_document_id(item): dict(item) for item in load_project_knowledge()}
    for item in external:
        if not isinstance(item, dict):
            continue
        identifier = _document_id(item)
        if identifier:
            merged[identifier] = dict(item)
    return list(merged.values())


def search_project_knowledge(
    query: str,
    *,
    top_k: int = 5,
    scope: list[str] | None = None,
    external: Iterable[dict[str, Any]] = (),
) -> list[dict[str, Any]]:
    documents = merge_knowledge_documents(external)
    allowed_scopes = set(scope or [])
    if allowed_scopes:
        documents = [item for item in documents if str(item.get("scope", "security")) in allowed_scopes]
    if not documents:
        return []

    query_tokens = _tokens(query)
    query_counts = Counter(query_tokens)
    document_tokens: list[Counter[str]] = []
    document_frequency: Counter[str] = Counter()
    for document in documents:
        title = str(document.get("title") or document.get("name") or "")
        tags = " ".join(str(tag) for tag in document.get("tags", []))
        content = str(document.get("content") or document.get("chunk") or document.get("summary") or "")
        weighted = (_tokens(title) * 4) + (_tokens(tags) * 3) + _tokens(content)
        counts = Counter(weighted)
        document_tokens.append(counts)
        document_frequency.update(counts.keys())

    total = len(documents)
    ranked: list[tuple[float, dict[str, Any]]] = []
    normalized_query = query.strip().lower()
    for document, counts in zip(documents, document_tokens):
        score = 0.0
        for token, query_weight in query_counts.items():
            if token not in counts:
                continue
            inverse_frequency = math.log((total + 1) / (document_frequency[token] + 0.5)) + 1
            score += query_weight * inverse_frequency * (1 + math.log1p(counts[token]))
        title = str(document.get("title") or "").lower()
        tags = " ".join(str(tag).lower() for tag in document.get("tags", []))
        if normalized_query and normalized_query in title:
            score += 12
        score += sum(3 for token in set(query_tokens) if len(token) > 1 and token in tags)
        if score > 0 or not query_tokens:
            result = dict(document)
            result["retrieval_score"] = round(score, 4)
            result["knowledge_version"] = KNOWLEDGE_VERSION
            ranked.append((score, result))

    ranked.sort(key=lambda pair: (-pair[0], _document_id(pair[1])))
    return [document for _, document in ranked[: max(1, min(top_k, 10))]]


def knowledge_manifest(external_count: int = 0) -> dict[str, Any]:
    scopes = sorted({str(item.get("scope", "security")) for item in load_project_knowledge()})
    return {
        "version": KNOWLEDGE_VERSION,
        "documents": len(load_project_knowledge()) + max(external_count, 0),
        "project_documents": len(load_project_knowledge()),
        "scopes": scopes,
        "retriever": "hybrid_lexical_cjk_v1",
        "labels_used_for_detection": False,
    }


def knowledge_document_catalog() -> list[dict[str, Any]]:
    return [
        {
            "id": _document_id(document),
            "name": str(document.get("title") or _document_id(document)),
            "category": "项目方法库",
            "kind": "内置知识",
            "status": "indexed",
            "chunks": 1,
            "updatedAt": "2026-08-16",
            "scope": str(document.get("scope", "project")),
            "tags": list(document.get("tags", [])),
        }
        for document in load_project_knowledge()
    ]
