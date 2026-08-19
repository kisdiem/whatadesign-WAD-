"""Export ATT&CK semantic cards and isolated weak-supervision records.

This script never reads target labels or split fields.  The optional mapping
inputs are only converted into supervision records after a strict provenance
and confidence filter, leaving EventFrame artifacts untouched.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from src.knowledge.attack_techniques import TechniqueSupervision, cards_from_stix


HIGH_PRECISION_RULES = {
    "T1059.001": 0.90,
    "T1003": 0.90,
    "T1053": 0.84,
    "T1110": 0.76,
    "T1505.003": 0.74,
}


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _find_bundle_objects(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict) and isinstance(value.get("objects"), list):
        return value["objects"]
    if isinstance(value, list):
        return value
    raise ValueError("STIX input must be a bundle with an objects array")


def export_cards(stix_path: Path, output: Path) -> int:
    cards = cards_from_stix(_find_bundle_objects(_read_json(stix_path)))
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for card in cards:
            handle.write(json.dumps(card.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
    return len(cards)


def export_high_precision_supervision(mapping_paths: list[Path], output: Path) -> int:
    """Extract only pre-approved high-confidence rule anchors.

    Scan candidates are deliberately excluded: T1595/T1046 requires context
    that a per-event rule cannot establish reliably.
    """
    records: dict[tuple[str, str], TechniqueSupervision] = {}
    for path in mapping_paths:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                row = json.loads(line)
                forbidden = {"target_label", "attack_label", "anomaly_label", "ground_truth", "split"} & set(row)
                if forbidden:
                    raise ValueError(f"{path}:{line_number} contains forbidden fields: {sorted(forbidden)}")
                for candidate in row.get("candidates", []):
                    technique_id = candidate.get("technique_id", "")
                    minimum = HIGH_PRECISION_RULES.get(technique_id)
                    if (minimum is None or candidate.get("disposition") != "candidate"
                            or candidate.get("mapping_source") != "structured_rule"
                            or float(candidate.get("confidence", 0.0)) < minimum):
                        continue
                    supervision = TechniqueSupervision(
                        record_id=row["record_id"],
                        technique_id=technique_id,
                        provenance="attack-candidate-rules-v1/high-precision-anchor",
                        confidence=float(candidate["confidence"]),
                        notes="Generated from behavior-specific rule; requires later template audit for release.",
                    )
                    records[(supervision.record_id, supervision.technique_id)] = supervision
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for key in sorted(records):
            handle.write(json.dumps(records[key].to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
    return len(records)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stix", type=Path, required=True)
    parser.add_argument("--cards-output", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, action="append", default=[])
    parser.add_argument("--supervision-output", type=Path)
    args = parser.parse_args()

    count = export_cards(args.stix, args.cards_output)
    print(json.dumps({"cards": count, "cards_output": str(args.cards_output)}, sort_keys=True))
    if args.supervision_output:
        if not args.mapping:
            raise SystemExit("--supervision-output requires at least one --mapping")
        anchors = export_high_precision_supervision(args.mapping, args.supervision_output)
        print(json.dumps({"high_precision_supervision": anchors, "supervision_output": str(args.supervision_output)}, sort_keys=True))


if __name__ == "__main__":
    main()
