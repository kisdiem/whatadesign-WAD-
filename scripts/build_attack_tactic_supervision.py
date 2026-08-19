"""Derive isolated ATT&CK tactic supervision from audited technique labels."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.knowledge.attack_techniques import TechniqueCard, TechniqueSupervision


TACTIC_DESCRIPTIONS = {
    "credential-access": "Obtain credentials, authentication material, or secrets from a defended environment.",
    "discovery": "Collect information about systems, accounts, processes, services, or network configuration.",
    "execution": "Execute commands, scripts, interpreters, or attacker-controlled code.",
    "lateral-movement": "Move from one system or session to another through remote services or shared access.",
    "persistence": "Maintain access across restarts, logons, or changes in user context.",
    "privilege-escalation": "Obtain higher permissions or execute with elevated privileges.",
    "stealth": "Hide activity, remove indicators, or evade security visibility.",
    "defense-impairment": "Disable, modify, or reduce a security control or its telemetry.",
}


def read_jsonl(path: Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield json.loads(line)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cards", type=Path, required=True)
    parser.add_argument("--supervision", type=Path, required=True)
    parser.add_argument("--card-output", type=Path, required=True)
    parser.add_argument("--supervision-output", type=Path, required=True)
    args = parser.parse_args()
    cards = {row["technique_id"]: TechniqueCard(**row) for row in read_jsonl(args.cards)}
    output: dict[tuple[str, str], TechniqueSupervision] = {}
    for row in read_jsonl(args.supervision):
        card = cards.get(row["technique_id"])
        if card is None:
            continue
        for tactic in card.tactics:
            if tactic not in TACTIC_DESCRIPTIONS:
                continue
            record = TechniqueSupervision(
                record_id=row["record_id"], technique_id=f"tactic:{tactic}",
                provenance=f"derived_tactic/{row['provenance']}", confidence=float(row["confidence"]),
                reviewer=row.get("reviewer"), notes=f"Derived only for tactic-level source supervision from {row['technique_id']}.",
            )
            output[(record.record_id, record.technique_id)] = record
    tactic_ids = sorted({row.technique_id for row in output.values()})
    args.card_output.parent.mkdir(parents=True, exist_ok=True)
    with args.card_output.open("w", encoding="utf-8") as handle:
        for tactic_id in tactic_ids:
            tactic = tactic_id.removeprefix("tactic:")
            handle.write(json.dumps(TechniqueCard(tactic_id, tactic.replace("-", " ").title(), (tactic,), TACTIC_DESCRIPTIONS[tactic]).to_dict(), sort_keys=True) + "\n")
    with args.supervision_output.open("w", encoding="utf-8") as handle:
        for key in sorted(output):
            handle.write(json.dumps(output[key].to_dict(), sort_keys=True) + "\n")
    print(json.dumps({"tactics": len(tactic_ids), "supervision_rows": len(output)}, sort_keys=True))


if __name__ == "__main__":
    main()
