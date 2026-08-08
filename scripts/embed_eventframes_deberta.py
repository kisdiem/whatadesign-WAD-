from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import _bootstrap
from src.common.schema import EventFrame
from src.semantic.deberta_security import FrozenDebertaSecurityEmbedder


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze-trained DeBERTa + Adapter EventFrame embedding export")
    parser.add_argument("--input", required=True, help="M1 EventFrame JSONL")
    parser.add_argument("--output", required=True)
    parser.add_argument("--mlm-dir", required=True)
    parser.add_argument("--adapter-checkpoint", required=True)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--device", default="cpu")
    args = parser.parse_args()
    input_path, output_path = Path(args.input), Path(args.output)
    frames = [EventFrame.from_dict(json.loads(line)) for line in input_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    embedder = FrozenDebertaSecurityEmbedder.load(args.mlm_dir, args.adapter_checkpoint, device=args.device)
    embedded = embedder.encode_frames(frames, batch_size=args.batch_size)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for frame in embedded:
            handle.write(json.dumps(frame.to_dict(), ensure_ascii=True) + "\n")
    manifest = {
        "status": "COMPLETED", "input": str(input_path), "input_sha256": sha256(input_path),
        "output": str(output_path), "output_sha256": sha256(output_path), "record_count": len(embedded),
        "embedding_dim": len(embedded[0].semantic_embedding or []) if embedded else 0,
        "semantic_version": "deberta_security_adapter_v1", "adapter_checkpoint": str(args.adapter_checkpoint),
        "classifier_used": False,
    }
    output_path.with_suffix(output_path.suffix + ".manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
