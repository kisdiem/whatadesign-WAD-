# M5 seed attack knowledge

This directory contains a deliberately small seed knowledge base for `M5KnowledgeProgressTransformer` external retrieval and cross-attention.

## Files

- `m5_seed_knowledge.jsonl`: concise ATT&CK-derived behavior records intended for semantic embedding and retrieval.
- `m5_seed_stage_schema.json`: the 10 coarse M5 progress positions used as soft priors.

## Scope

The seed set intentionally favors behaviors that commonly leave useful host, identity, process, file or network evidence and that cover a representative attack chain:

`initial access -> execution -> foothold/persistence -> credential access -> discovery -> lateral movement -> C2 -> collection -> exfiltration -> impact`

The seed currently contains 17 Enterprise ATT&CK techniques/sub-techniques, including Phishing, Valid Accounts, PowerShell, Windows Command Shell, Scheduled Task, Registry Run Keys, LSASS Memory, domain/system/remote-system discovery, RDP, SMB admin shares, Ingress Tool Transfer, Web Protocols, Archive via Utility, Exfiltration Over C2 Channel and Data Encrypted for Impact.

The source baseline is MITRE ATT&CK Enterprise 19.1. Text in this repository is concise project-oriented paraphrase rather than a copy of full ATT&CK descriptions. Each record keeps the official ATT&CK ID and source URL for traceability.

## Record fields

Each JSONL row contains:

- `knowledge_id`: stable local identifier.
- `attack_id`: ATT&CK technique/sub-technique ID.
- `name`: technique name.
- `primary_tactic`: primary coarse tactic used for this seed record; not intended to be exhaustive.
- `positions`: one or more M5 model stage indices.
- `progress`: soft continuous progress prior in `[0,1]`.
- `text`: concise semantic description used for embedding.
- `log_clues`: short observable clues that can be appended to the embedding text.
- `source_url`: official ATT&CK reference.

## How it reaches cross-attention

The committed JSONL is raw semantic knowledge, not a fabricated vector file. Build-time code should encode each record with the selected knowledge encoder, then attach the resulting vector as `embedding` and pass records into `AttackKnowledgeIndex.from_records(...)`.

Recommended embedding text:

`name + primary_tactic + text + log_clues`

The current M5 knowledge model uses an internal candidate cap and Top-K retrieval before external-knowledge cross-attention. Do not send an unbounded knowledge database directly into cross-attention.

## Leakage boundary

Do not convert target-test labels, target scenario ground truth, or post-hoc analyst answers into knowledge records. Public ATT&CK content and training-domain knowledge are allowed; target evaluation labels are not.

## Position semantics

The 10 positions are model priors, not an official ATT&CK timeline. ATT&CK tactics are not strictly linear and campaigns may revisit earlier behaviors. The downstream transition compatibility matrix remains learnable, and progress remains a soft feature rather than a hard ordering rule.
