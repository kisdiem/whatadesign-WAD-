from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path


ROOT = Path(r"E:\wad-demo-data")
SOURCES = {
    "Short": Path(r"E:\harrison.zip"),
    "Long": Path(r"E:\wardbeck.zip"),
}


def read_lines(source: Path, member: str) -> list[str]:
    with zipfile.ZipFile(source) as archive:
        return archive.read(member).decode("utf-8", "replace").splitlines()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    auth_member = "gather/intranet_server/logs/auth.log"
    harrison_lines = read_lines(SOURCES["Short"], auth_member)
    wardbeck_lines = read_lines(SOURCES["Long"], auth_member)
    short_lines = [line for line in harrison_lines if line.startswith(("Feb  8 08:36", "Feb  8 08:37", "Feb  8 08:38", "Feb  8 08:39"))]
    long_lines = [line for line in wardbeck_lines if line.startswith(("Jan 23 12:55", "Jan 23 12:56", "Jan 23 12:57"))]

    for label, lines, window in [
        ("Short", short_lines, "2022-02-08T08:36:38+00:00/2022-02-08T08:39:01+00:00"),
        ("Long", long_lines, "2022-01-23T12:55:01+00:00/2022-01-23T12:55:19+00:00"),
    ]:
        target = ROOT / label
        target.mkdir(parents=True, exist_ok=True)
        raw = "\n".join(lines) + "\n"
        (target / "events.log").write_text(raw, encoding="utf-8")
        events = [
            {
                "event_id": f"{label.upper()}-{index:04d}",
                "source_file": auth_member,
                "raw": line,
                "facts_only": True,
            }
            for index, line in enumerate(lines, 1)
        ]
        write_json(target / "events.json", events)
        write_json(target / "attack_chain.json", {
            "chain_id": f"{label.upper()}-CANDIDATE-001",
            "status": "candidate",
            "claim_type": "analyst_curated_replay",
            "steps": [
                {"sequence": 1, "label": "session transition", "evidence_event_ids": [f"{label.upper()}-0001"]},
                {"sequence": 2, "label": "privileged command context", "evidence_event_ids": [f"{label.upper()}-0006", f"{label.upper()}-0007"]},
                {"sequence": 3, "label": "host and account discovery", "evidence_event_ids": [f"{label.upper()}-{min(10, len(lines)):04d}"]},
            ],
            "limitations": [
                "This is a manually curated replay package, not a model prediction.",
                "The chain is a candidate interpretation of source log facts.",
                "AIT ground-truth labels and source labels are excluded from this package.",
            ],
        })
        write_json(target / "manifest.json", {
            "dataset_id": label,
            "kind": "demo_replay",
            "source_archive": SOURCES[label].name,
            "source_member": auth_member,
            "source_slice": window,
            "event_count": len(lines),
            "sha256_events_log": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            "contains_labels": False,
            "contains_facts_json": False,
            "generated_at": "2026-08-14T00:00:00Z",
        })


if __name__ == "__main__":
    main()
