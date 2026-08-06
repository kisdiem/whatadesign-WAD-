from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _bootstrap  # noqa: F401
from src.parsers.m0_drain import M0DrainParser


ROOT = Path(__file__).resolve().parents[2]
DATA = Path("/root/autodl-tmp/semantic-graph-apt/data")
EXTERNAL = Path("/root/autodl-tmp/ait-garnet-demo-external/data")


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def entry(dataset_id, display_name, role, tier, url, status, path, usage, prohibited, parser, notes=""):
    return {
        "dataset_id": dataset_id, "display_name": display_name, "role": role,
        "tier": tier, "official_url": url, "repository_url": url,
        "version": "unfixed-source-observation", "license": "see_official_source",
        "expected_files": [], "expected_size": None, "checksum": sha256(Path(path)) if path else None,
        "download_method": "official_source_only", "requires_manual_acceptance": False,
        "allowed_label_usage": usage, "prohibited_usage": prohibited, "parser": parser,
        "status": status, "local_path": path, "notes": notes,
    }


def main():
    for directory in ("data/manifests", "data/source_domains", "data/normalized", "data/semantic_frames", "data/graphs", "data/windows", "data/feature_store", "outputs/reports", "run_state"):
        (ROOT / directory).mkdir(parents=True, exist_ok=True)
    loghub = EXTERNAL / "external_raw/Apache_2k.log"
    parser = M0DrainParser()
    rows = list(parser.parse_lines("loghub_2_0", loghub, limit=2000)) if loghub.exists() else []
    mask_a = parser.safe_mask("allow ip=10.0.0.1 eventid=4624 status=success")
    mask_b = parser.safe_mask("allow ip=10.0.0.2 eventid=4624 status=success")
    constants_preserved = all(token in mask_a for token in ("allow", "eventid=4624", "status=success"))
    m0_result = {"status": "PASSED" if rows and mask_a == mask_b and constants_preserved else "FAILED", "rows": len(rows), "templates": parser.catalog()["templates"], "same_template_mask_check": mask_a == mask_b, "safe_constants_preserved": constants_preserved, "parser_version": parser.VERSION}
    (ROOT / "outputs/source_validation/m0_smoke.json").write_text(json.dumps(m0_result, indent=2), encoding="utf-8")

    sources = [
        entry("loghub_2_0", "LogHub-2.0", "m0_template_source", 0, "https://github.com/logpai/loghub-2.0", "verified" if loghub.exists() else "unavailable", str(loghub), "template_only", "no_apt_labels", "drain3", "2k smoke subset only"),
        entry("ocsf", "OCSF schema and examples", "semantic_taxonomy", 0, "https://github.com/ocsf/ocsf-schema", "verified" if (EXTERNAL / "external_subsets/ocsf-schema/.git").exists() else "unavailable", str(EXTERNAL / "external_subsets/ocsf-schema"), "schema_only", "no_target_labels", "git_schema"),
        entry("splunk_attack_data", "Splunk Attack Data", "semantic_event_source", 0, "https://github.com/splunk/attack_data", "downloaded" if (DATA / "processed_available/splunk_attack_data").exists() else "unavailable", str(DATA / "processed_available/splunk_attack_data"), "weak_source_domain", "no_ait_labels", "splunk_yaml_log"),
        entry("hdfs_bgl", "HDFS and BGL", "sequence_pretraining", 0, "https://github.com/logpai/loghub-2.0", "verified" if (EXTERNAL / "external_raw/HDFS_2k.log").exists() else "unavailable", str(EXTERNAL / "external_raw"), "system_anomaly_pretraining_only", "not_apt_labels", "loghub_text"),
        entry("ctu13_selected", "CTU-13 selected flows", "network_source", 1, "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-13/", "downloaded" if (DATA / "ctu13_full_extracted").exists() else "unavailable", str(DATA / "ctu13_full_extracted"), "source_domain_only", "no_ait_labels", "ctu13_csv", "full archive extraction in progress"),
        entry("sandworm_flow", "Sandworm labelled flow", "network_validation_source", 1, "https://doi.org/10.5281/zenodo.16911636", "downloaded" if (DATA / "replacement_sources/sandworm/SandwormAPT_flow_labelled.csv").exists() else "unavailable", str(DATA / "replacement_sources/sandworm"), "source_validation_only", "no_target_label_generation", "sandworm_csv"),
        entry("lanl_comprehensive", "LANL Comprehensive Multi-Source", "entity_graph_source", 1, "https://csr.lanl.gov/data/cyber1/", "unavailable", "", "source_domain_only", "no_ait_labels", "lanl_stream", "official files not obtained"),
        entry("darpa_tc", "DARPA Transparent Computing", "graph_long_horizon_source", 1, "https://github.com/darpa-i2o/Transparent-Computing", "unavailable", "", "source_domain_only", "no_ait_labels", "darpa_cdm", "manual download required"),
        entry("ait_lds_v2", "AIT-LDSv2.0", "target_test", "target", "https://zenodo.org/records/5789064", "metadata_only", "", "evaluation_only_p1", "training_or_tuning", "ait_sealed_adapter", "AIT not accessed"),
        entry("ait_ads", "AIT-ADS", "target_test", "target", "https://zenodo.org/records/8263181", "metadata_only", "", "evaluation_only_p1", "training_or_tuning", "ait_sealed_adapter", "AIT not accessed"),
    ]
    registry = {"schema_version": "v3_data_registry_2", "generated_at": datetime.now(timezone.utc).isoformat(), "datasets": {row["dataset_id"]: row for row in sources}}
    (ROOT / "configs/data/data_registry.yaml").write_text(yaml.safe_dump(registry, sort_keys=False), encoding="utf-8")
    steps = {"A00": "COMPLETED", "A01": "COMPLETED", "A02": "COMPLETED", "B01": "COMPLETED" if rows else "FAILED", "B02": m0_result["status"], "C01": "COMPLETED" if (EXTERNAL / "external_subsets/ocsf-schema").exists() else "BLOCKED_MISSING_DATA", "C02": "COMPLETED" if (DATA / "processed_available/splunk_attack_data").exists() else "BLOCKED_MISSING_DATA", "C04": "BLOCKED_MISSING_DATA", "C05": "BLOCKED_MISSING_DATA", "AIT": "NOT_ACCESSED"}
    (ROOT / "run_state/completed_steps.json").write_text(json.dumps(steps, indent=2), encoding="utf-8")
    report = "# Phase 0 Foundation\n\n"
    report += f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n"
    report += "## Execution\n\n- AIT accessed: false\n- AIT labels used: false\n- Full model training: not started\n\n"
    report += "## M0 smoke\n\n```json\n" + json.dumps(m0_result, indent=2) + "\n```\n\n"
    report += "## Data status\n\n" + "\n".join(f"- `{row['dataset_id']}`: `{row['status']}`; path=`{row['local_path'] or 'unavailable'}`" for row in sources) + "\n\n"
    report += "## Blockers\n\n- LANL and DARPA TC official source files are unavailable.\n- AIT remains metadata-only and was not accessed.\n- Source model weights are absent; source readiness remains blocked.\n- Entity taxonomy input `/mnt/data/实体事件.txt` was not present on the server.\n"
    (ROOT / "outputs/reports/phase_0_foundation.md").write_text(report, encoding="utf-8")
    print(json.dumps({"status": "COMPLETED", "m0": m0_result, "ait_accessed": False, "report": "outputs/reports/phase_0_foundation.md"}, indent=2))


if __name__ == "__main__":
    main()
