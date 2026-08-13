from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path
from statistics import median

import _bootstrap
from src.detection.engine import DetectionEngine
from src.detection.schema import load_jsonl, write_json


def confusion(scores: dict[str, float], labels: dict[str, int], threshold: float) -> dict[str, float | int]:
    tp = fp = tn = fn = 0
    for event_id, label in labels.items():
        predicted = scores.get(event_id, 0.0) >= threshold
        if label and predicted: tp += 1
        elif label: fn += 1
        elif predicted: fp += 1
        else: tn += 1
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    false_positive_ids = [event_id for event_id, label in labels.items() if not label and scores.get(event_id, 0.0) >= threshold]
    false_negative_ids = [event_id for event_id, label in labels.items() if label and scores.get(event_id, 0.0) < threshold]
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "f1": 2 * precision * recall / max(precision + recall, 1e-12), "fpr": fpr, "false_positives_per_million": fpr * 1_000_000, "false_positive_event_ids": false_positive_ids, "false_negative_event_ids": false_negative_ids}


def average_precision(scores: dict[str, float], labels: dict[str, int]) -> float:
    ranked = sorted(labels, key=lambda event_id: scores.get(event_id, 0.0), reverse=True)
    positives = sum(labels.values())
    hits = 0
    total = 0.0
    for rank, event_id in enumerate(ranked, 1):
        if labels[event_id]:
            hits += 1
            total += hits / rank
    return total / max(positives, 1)


def chain_recovery(windows: list[dict], chains: dict[str, list[str]]) -> float:
    sets = [{event["event_id"] for event in window["events"]} for window in windows]
    recovered = sum(any(set(events).issubset(candidate) for candidate in sets) for events in chains.values())
    return recovered / max(len(chains), 1)


def evaluate_variant(engine: DetectionEngine, events, labels, chains, variant: str, include_chain: bool = True) -> dict:
    scored = engine.score_events(events, variant=variant)
    windows = engine._windows(scored, include_chain=include_chain)
    scores = {row["event_id"]: float(row["risk_score"]) for row in scored}
    metrics = confusion(scores, labels, engine.config.event_threshold)
    metrics.update({"pr_auc": average_precision(scores, labels), "chain_recovery": chain_recovery(windows, chains), "finding_count": len(windows)})
    return metrics


def benchmark(engine: DetectionEngine, events, repeats: int, target_records: int = 10_000) -> dict:
    benchmark_events = (events * math.ceil(target_records / len(events)))[:target_records]
    samples = []
    for _ in range(repeats):
        started = time.perf_counter()
        engine.score_events(benchmark_events)
        samples.append(len(benchmark_events) / max(time.perf_counter() - started, 1e-9))
    return {"records": len(benchmark_events), "repeats": repeats, "median_events_per_second": median(samples), "min_events_per_second": min(samples), "max_events_per_second": max(samples), "benchmark_mode": "bundled sample records repeated to a fixed workload", "scope": "single-process in-memory scoring; excludes disk I/O"}


def markdown(report: dict) -> str:
    full = report["metrics"]
    lines = [
        "# WAD 可复现评测报告", "", f"生成命令：`{report['reproduce_command']}`", "",
        "> 结果来自仓库内的有标签演示集，仅证明端到端评测链路可复现，不代表生产数据集性能。真实标签在预测完成后由本脚本独立读取。", "",
        "## 核心指标", "",
        "| Precision | Recall | F1 | FPR | PR-AUC | 攻击链恢复率 |", "|---:|---:|---:|---:|---:|---:|",
        f"| {full['precision']:.3f} | {full['recall']:.3f} | {full['f1']:.3f} | {full['fpr']:.3f} | {full['pr_auc']:.3f} | {full['chain_recovery']:.3f} |", "",
        "## 消融实验", "", "| 版本 | Recall | FPR | PR-AUC | 攻击链恢复率 |", "|---|---:|---:|---:|---:|",
    ]
    for name, value in report["ablations"].items():
        lines.append(f"| {name} | {value['recall']:.3f} | {value['fpr']:.3f} | {value['pr_auc']:.3f} | {value['chain_recovery']:.3f} |")
    unsupervised = report["ablations"]["unsupervised_only"]
    lines.extend(["", "## 吞吐", "", f"固定 10,000 条重复样例的单进程内存打分中位数：**{report['throughput']['median_events_per_second']:.0f} EPS**。该数字不包含磁盘读取，不外推为 TB 级实测。", "", "## 误报", "", f"完整方案 FP={full['fp']}，TN={full['tn']}，每百万正常日志误报数={full['false_positives_per_million']:.0f}。", f"无监督单模块误报事件：{', '.join(unsupervised['false_positive_event_ids']) or '无'}；这些样本由弱监督投票帮助抑制。", ""])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--repeats", type=int, default=7)
    args = parser.parse_args()
    events = list(load_jsonl(args.input))
    # Evaluation labels are opened only after the detector has scored the unlabelled events.
    engine = DetectionEngine()
    scored = engine.score_events(events)
    label_payload = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    labels = {key: int(value) for key, value in label_payload["labels"].items()}
    chains = label_payload.get("chains", {})
    scores = {row["event_id"]: float(row["risk_score"]) for row in scored}
    windows = engine._windows(scored)
    metrics = confusion(scores, labels, engine.config.event_threshold)
    metrics.update({"pr_auc": average_precision(scores, labels), "chain_recovery": chain_recovery(windows, chains), "finding_count": len(windows)})
    ablations = {
        "full": metrics,
        "unsupervised_only": evaluate_variant(engine, events, labels, chains, "unsupervised_only"),
        "weak_only": evaluate_variant(engine, events, labels, chains, "weak_only"),
        "without_entity_rarity": evaluate_variant(engine, events, labels, chains, "without_entity_rarity"),
        "without_chain_aggregation": evaluate_variant(engine, events, labels, chains, "full", False),
    }
    command = f"python scripts/evaluate_detection.py --input {args.input} --labels {args.labels} --output-dir {args.output_dir}"
    report = {"status": "COMPLETED", "dataset_scope": "labelled_demo_only", "labels_used_for_training": False, "labels_read_after_prediction": True, "metrics": metrics, "ablations": ablations, "throughput": benchmark(engine, events, max(args.repeats, 1)), "reproduce_command": command}
    target = Path(args.output_dir)
    write_json(target / "evaluation_report.json", report)
    (target / "evaluation_report.md").write_text(markdown(report), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
