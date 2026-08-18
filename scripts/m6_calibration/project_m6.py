"""Short/Long 演示数据的 M6 重投影脚本。

流程：
  1. 读取四源统计基线 outputs/m6_calibration/baseline.json（由 scan_sources.py 生成）。
  2. 对 demo-data/{Short,Long}/timeline.json 的每个事件，按与 agent_service/ingestion.py
     同一套口径计算 M0-M6：
       - M1 弱监督信号：规则与上传链路一致；
       - M2 实体稀有度 = 文件内稀有度 × 基线常见性惩罚（真实日志中高频实体降权）；
       - M3 实体图上下文：基于事件实体数量；
       - M4 模板稀有度 = 文件内模板稀有度 × 基线模板常见性惩罚，失败上下文加成；
       - M5 长程关联：共享实体的较早风险事件（时间序）；
       - M6 = 0.30*M1 + 0.12*M2 + 0.14*M3 + 0.28*M4 + 0.16*M5（与上传链路融合公式一致）。
  3. 输出 frontend/public/demo-data/{Short,Long}/module_scores.json。

隔离纪律：全程不读取任何标签文件/EVTX_Tactic 列；产物标注
labels_used=false、synthetic_scores=true（重投影，非对四源执行完整检测）。

用法：
  python scripts/m6_calibration/project_m6.py [--baseline outputs/m6_calibration/baseline.json]
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _scoring import clamp, extract_entities, template_fingerprint, weak_supervision  # noqa: E402


def load_baseline(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    distributions = data["distributions"]
    return {
        "entity_freq": distributions["entity_frequency"],
        "template_freq": distributions["template_frequency"],
        "total_lines": data["counts"]["lines_scanned"],
        "generated_at": data["generated_at"],
    }


def _rarity(count: int) -> float:
    return clamp(1 / math.sqrt(max(count, 1)))


def _baseline_factor(freq_map: dict[str, int], key: str) -> float:
    """真实日志基线常见性惩罚：高频实体/模板降权，缺失保持默认。"""
    freq = freq_map.get(key, 0)
    if freq <= 0:
        return 1.0
    return clamp(0.5 + 0.5 / (1 + math.log10(freq + 1)))


def score_dataset(dataset_id: str, timeline: list[dict[str, Any]], baseline: dict[str, Any]) -> dict[str, dict[str, float]]:
    entity_freq = baseline["entity_freq"]
    template_freq = baseline["template_freq"]
    baseline_lines = max(baseline["total_lines"], 1)

    # 文件内统计：实体频率、模板频率、风险事件时间序。
    file_entity_counts: Counter[str] = Counter()
    file_template_counts: Counter[str] = Counter()
    entities_by_event: dict[str, list[str]] = {}
    ordered: list[tuple[str, list[str], float, str]] = []  # (event_id, entity_keys, weak, raw)
    for item in timeline:
        event_id = str(item.get("event_id", ""))
        raw = str(item.get("raw", "") or "")
        entities = extract_entities(raw, None)
        keys = [f"{entity_type}:{value}" for entity_type, values in entities.items() for value in values]
        for key in keys:
            file_entity_counts[key] += 1
        fingerprint = template_fingerprint(raw)
        file_template_counts[fingerprint] += 1
        weak_score, _ = weak_supervision(raw)
        entities_by_event[event_id] = keys
        ordered.append((event_id, keys, weak_score, raw))

    # M3 实体图上下文：跨事件共现对（共享实体的新颖度来源）。
    cooccurrence: Counter[str] = Counter()
    seen_pairs: set[tuple[str, str]] = set()
    for keys in entities_by_event.values():
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                pair = tuple(sorted((keys[i], keys[j])))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    cooccurrence[pair[0] + "|" + pair[1]] += 1

    # M5 长程关联：按时间序维护"较早风险事件"，共享实体即关联。
    previous_risky: list[tuple[str, set[str]]] = []
    result: dict[str, dict[str, float]] = {}
    for event_id, keys, weak_score, raw in ordered:
        key_set = set(keys)
        linked = [entry for entry in previous_risky[-100:] if key_set & entry[1]]
        m5 = clamp(0.12 + min(len(linked), 3) * 0.22 + (0.18 if weak_score >= 0.6 and linked else 0))

        entity_rarities: list[float] = []
        for key in keys:
            file_rarity = _rarity(file_entity_counts[key])
            factor = _baseline_factor(entity_freq.get(key.split(":", 1)[0], {}), key)
            entity_rarities.append(file_rarity * factor)
        m2 = clamp(0.2 + 0.55 * (max(entity_rarities, default=0.25)))

        m3 = clamp(0.12 + min(len(keys), 5) * 0.09 + (0.20 if len(keys) >= 2 else 0))

        fingerprint = template_fingerprint(raw)
        file_template_rarity = _rarity(file_template_counts[fingerprint])
        template_factor = _baseline_factor(template_freq, fingerprint)
        template_rarity = clamp(file_template_rarity * template_factor)
        failure_boost = 0.22 if any(token in raw.lower() for token in ("failed", "failure", "denied")) else 0
        m4 = clamp(0.16 + 0.62 * template_rarity + failure_boost)

        m1 = weak_score
        m0 = 0.9
        m6 = clamp(0.30 * m1 + 0.12 * m2 + 0.14 * m3 + 0.28 * m4 + 0.16 * m5)

        result[event_id] = {
            "M0": round(m0, 4),
            "M1": round(m1, 4),
            "M2": round(m2, 4),
            "M3": round(m3, 4),
            "M4": round(m4, 4),
            "M5": round(m5, 4),
            "M6": round(m6, 4),
        }
        if weak_score >= 0.6 or (m6 >= 0.45 and keys):
            previous_risky.append((event_id, key_set))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Short/Long 演示数据 M6 重投影")
    parser.add_argument("--baseline", type=str, default=str(ROOT / "outputs/m6_calibration/baseline.json"))
    args = parser.parse_args()

    baseline_path = Path(args.baseline)
    if not baseline_path.exists():
        raise SystemExit(f"基线文件不存在：{baseline_path}。请先运行 scan_sources.py 全量扫描。")
    baseline = load_baseline(baseline_path)

    summary: dict[str, Any] = {}
    for dataset in ("Short", "Long"):
        dataset_dir = ROOT / f"frontend/public/demo-data/{dataset}"
        timeline_path = dataset_dir / "timeline.json"
        if not timeline_path.exists():
            print(f"[skip] 未找到 {timeline_path}", file=sys.stderr)
            continue
        timeline = json.loads(timeline_path.read_text(encoding="utf-8"))
        scores = score_dataset(dataset, timeline, baseline)
        output = dataset_dir / "module_scores.json"
        output.write_text(json.dumps(scores, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        m6_values = [entry["M6"] for entry in scores.values()]
        summary[dataset] = {
            "events": len(scores),
            "m6_min": round(min(m6_values), 4),
            "m6_max": round(max(m6_values), 4),
            "m6_mean": round(sum(m6_values) / max(len(m6_values), 1), 4),
            "output": str(output),
        }
        print(json.dumps({dataset: summary[dataset]}, ensure_ascii=False))

    meta = {
        "schema_version": "m6_projection_v1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "baseline": str(baseline_path),
        "baseline_generated_at": baseline["generated_at"],
        "labels_used": False,
        "synthetic_scores": True,
        "model_execution": False,
        "note": "Short/Long 演示分数为基于四源真实日志统计标定的 M6 重投影，规则与上传链路 M0-M6 口径一致。",
        "fusion_formula": "M6 = 0.30*M1 + 0.12*M2 + 0.14*M3 + 0.28*M4 + 0.16*M5",
        "datasets": summary,
    }
    meta_path = ROOT / "outputs/m6_calibration/projection_meta.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"meta": str(meta_path), "labels_used": False}, ensure_ascii=False))


if __name__ == "__main__":
    main()
