"""Fetch a small, auditable Splunk Attack Data subset.

The script starts with YAML metadata only.  Raw logs are downloaded only with
``--include-logs`` and every result is recorded in a manifest.  ATT&CK IDs in
the source directory are provenance for a reviewer, never fields injected into
an EventFrame or model input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen


LOG_SUFFIXES = {".log", ".json", ".jsonl", ".evtx", ".xml"}
METADATA_SUFFIXES = {".yml", ".yaml"}


def request_json(url: str) -> Any:
    with urlopen(Request(url, headers={"Accept": "application/vnd.github+json"}), timeout=45) as response:  # nosec B310: fixed GitHub API host supplied by config
        return json.loads(response.read().decode("utf-8"))


def download(url: str) -> bytes:
    with urlopen(Request(url), timeout=90) as response:  # nosec B310: URL comes from GitHub API response
        return response.read()


def list_tree(api_root: str, repository: str, ref: str, path: str) -> list[dict[str, Any]]:
    """Recursively list files below one selected technique directory."""
    url = f"{api_root}/repos/{repository}/contents/{quote(path)}?ref={quote(ref)}"
    payload = request_json(url)
    if not isinstance(payload, list):
        payload = [payload]
    files: list[dict[str, Any]] = []
    for item in payload:
        if item["type"] == "file":
            files.append(item)
        elif item["type"] == "dir":
            files.extend(list_tree(api_root, repository, ref, item["path"]))
    return files


def is_lfs_pointer(payload: bytes) -> bool:
    return payload.startswith(b"version https://git-lfs.github.com/spec/v1\n")


def fetch_subset(config: dict[str, Any], output_root: Path, include_logs: bool) -> list[dict[str, Any]]:
    api_root = "https://api.github.com"
    output_root.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    for technique_id in config["techniques"]:
        source_path = f"datasets/attack_techniques/{technique_id}"
        for item in list_tree(api_root, config["repository"], config["ref"], source_path):
            path = Path(item["path"])
            suffix = path.suffix.lower()
            selected = suffix in METADATA_SUFFIXES or (include_logs and suffix in LOG_SUFFIXES)
            if not selected:
                continue
            relative = Path(technique_id) / path.relative_to(source_path)
            destination = output_root / relative
            entry = {
                "source_repository": config["repository"],
                "source_ref": config["ref"],
                "source_path": item["path"],
                "source_url": item["html_url"],
                "technique_directory": technique_id,
                "split_group": str(relative.parent),
                "kind": "metadata" if suffix in METADATA_SUFFIXES else "raw_log",
                "status": "listed",
            }
            try:
                payload = download(item["download_url"])
                if is_lfs_pointer(payload):
                    entry["status"] = "lfs_pointer_not_ingested"
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(payload)
                    entry.update({
                        "status": "downloaded",
                        "local_path": str(destination),
                        "bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    })
            except Exception as exc:  # keep the failed source observable and retryable
                entry.update({"status": "download_failed", "error": str(exc)})
            entries.append(entry)
    return entries


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--include-logs", action="store_true")
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    entries = fetch_subset(config, args.output_root, args.include_logs)
    manifest = args.output_root / "manifest.jsonl"
    manifest.write_text("".join(json.dumps(entry, sort_keys=True) + "\n" for entry in entries), encoding="utf-8")
    summary = {"downloaded": 0, "failed": 0, "lfs_pointers": 0, "listed": len(entries)}
    for entry in entries:
        summary["downloaded"] += entry["status"] == "downloaded"
        summary["failed"] += entry["status"] == "download_failed"
        summary["lfs_pointers"] += entry["status"] == "lfs_pointer_not_ingested"
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
