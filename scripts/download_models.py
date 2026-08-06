from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from huggingface_hub import HfApi, snapshot_download
from transformers import AutoConfig


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-root", default=os.environ.get("MODEL_CACHE_ROOT", "/root/autodl-tmp/semantic-graph-apt/model_cache"))
    args = parser.parse_args()
    root = Path(args.cache_root)
    root.mkdir(parents=True, exist_ok=True)
    specs = {
        "m1": {"id": "microsoft/deberta-v3-base", "mode": "finetune", "expected_hidden_size": 768},
        "m4": {"id": "Qwen/Qwen3-1.7B-Base", "mode": "frozen", "expected_hidden_size": 2048},
        "m4_smoke": {"id": "Qwen/Qwen3-0.6B-Base", "mode": "frozen", "release_eligible": False},
    }
    api = HfApi()
    result = {"status": "COMPLETED", "models": {}, "download_allowed": True}
    for name, spec in specs.items():
        repo_id = spec["id"]
        target = root / name
        info = api.model_info(repo_id)
        snapshot_download(
            repo_id=repo_id,
            local_dir=str(target),
            local_dir_use_symlinks=False,
            resume_download=True,
            allow_patterns=["config.json", "*.json", "*.txt", "*.model", "*.safetensors", "pytorch_model.bin", "tokenizer*"],
            ignore_patterns=["tf_model.h5", "rust_model.ot", "flax_model.msgpack"],
        )
        config = AutoConfig.from_pretrained(str(target), local_files_only=True)
        hidden = int(getattr(config, "hidden_size", -1))
        expected = spec.get("expected_hidden_size")
        if expected is not None and hidden != expected:
            raise RuntimeError(f"{repo_id}: hidden_size={hidden}, expected={expected}")
        files = {str(path.relative_to(target)): sha256(path) for path in target.rglob("*") if path.is_file() and ".cache" not in path.parts}
        result["models"][name] = {"id": repo_id, "revision": info.sha, "mode": spec["mode"], "hidden_size": hidden, "files": files, "release_eligible": spec.get("release_eligible", False)}
    (root / "model_download_manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"status": result["status"], "models": {key: {"id": value["id"], "revision": value["revision"], "hidden_size": value["hidden_size"]} for key, value in result["models"].items()}}, indent=2))


if __name__ == "__main__":
    main()
