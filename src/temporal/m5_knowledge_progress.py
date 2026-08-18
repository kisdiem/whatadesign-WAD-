from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

import torch
from torch import Tensor, nn
import torch.nn.functional as F


@dataclass(frozen=True)
class M5KnowledgeConfig:
    """Configuration for knowledge-augmented attack-progress estimation."""

    vocab_size: int = 32768
    max_seq_len: int = 192
    d_model: int = 128
    semantic_input_dim: int | None = None
    num_heads: int = 4
    encoder_layers: int = 2
    feedforward_dim: int = 256
    dropout: float = 0.1
    num_positions: int = 10
    knowledge_top_k: int = 16
    knowledge_candidate_cap: int = 128
    retrieval_temperature: float = 0.07
    broad_attack_threshold: float = 0.35
    version: str = "m5_knowledge_progress_v1"

    def __post_init__(self) -> None:
        if self.d_model % self.num_heads != 0:
            raise ValueError("d_model must be divisible by num_heads")
        if self.max_seq_len <= 0 or self.vocab_size <= 1:
            raise ValueError("max_seq_len and vocab_size must be positive")
        if self.num_positions <= 0 or self.knowledge_top_k <= 0 or self.knowledge_candidate_cap <= 0:
            raise ValueError("num_positions, knowledge_top_k and knowledge_candidate_cap must be positive")
        if self.knowledge_top_k > self.knowledge_candidate_cap:
            raise ValueError("knowledge_top_k cannot exceed knowledge_candidate_cap")
        if self.retrieval_temperature <= 0:
            raise ValueError("retrieval_temperature must be positive")
        if not 0.0 < self.broad_attack_threshold < 1.0:
            raise ValueError("broad_attack_threshold must be in (0, 1)")


@dataclass(frozen=True)
class AttackKnowledgeIndex:
    """Runtime index built from external ATT&CK/attack-chain knowledge.

    `embeddings` are precomputed offline; inference retrieves only Top-K entries.
    `position_targets` is multi-hot because one knowledge item may match several
    attack-chain positions. `progress` is a generic chain-position prior in [0, 1].
    """

    embeddings: Tensor
    position_targets: Tensor
    progress: Tensor
    knowledge_ids: tuple[str, ...] = ()

    def validate(self, d_model: int, num_positions: int) -> None:
        if self.embeddings.ndim != 2 or self.embeddings.shape[1] != d_model:
            raise ValueError("knowledge embeddings must have shape [knowledge_count, d_model]")
        count = self.embeddings.shape[0]
        if count == 0:
            raise ValueError("knowledge index cannot be empty")
        if self.position_targets.shape != (count, num_positions):
            raise ValueError("position_targets must have shape [knowledge_count, num_positions]")
        if self.progress.shape != (count,):
            raise ValueError("progress must have shape [knowledge_count]")
        if not torch.isfinite(self.embeddings).all():
            raise ValueError("knowledge embeddings must be finite")
        if not torch.isfinite(self.position_targets).all() or torch.any((self.position_targets < 0) | (self.position_targets > 1)):
            raise ValueError("knowledge position targets must be finite and in [0, 1]")
        if not torch.isfinite(self.progress).all() or torch.any((self.progress < 0) | (self.progress > 1)):
            raise ValueError("knowledge progress values must be finite and in [0, 1]")
        if self.knowledge_ids and len(self.knowledge_ids) != count:
            raise ValueError("knowledge_ids length must match knowledge_count")

    @classmethod
    def from_records(
        cls,
        records: Iterable[dict[str, object]],
        *,
        d_model: int,
        num_positions: int,
        dtype: torch.dtype = torch.float32,
    ) -> "AttackKnowledgeIndex":
        embeddings: list[Tensor] = []
        positions: list[Tensor] = []
        progress: list[float] = []
        ids: list[str] = []
        for row_no, row in enumerate(records):
            vector = torch.as_tensor(row["embedding"], dtype=dtype)
            if vector.shape != (d_model,):
                raise ValueError(f"knowledge row {row_no} embedding must have shape [{d_model}]")
            mask = torch.zeros(num_positions, dtype=dtype)
            for position in row.get("positions", []):
                position = int(position)
                if not 0 <= position < num_positions:
                    raise ValueError(f"knowledge row {row_no} position out of range")
                mask[position] = 1.0
            value = float(row["progress"])
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"knowledge row {row_no} progress must be in [0, 1]")
            embeddings.append(vector)
            positions.append(mask)
            progress.append(value)
            ids.append(str(row.get("knowledge_id", f"knowledge_{row_no:06d}")))
        if not embeddings:
            raise ValueError("knowledge records cannot be empty")
        index = cls(torch.stack(embeddings), torch.stack(positions), torch.tensor(progress, dtype=dtype), tuple(ids))
        index.validate(d_model, num_positions)
        return index

    def to(self, device: torch.device | str) -> "AttackKnowledgeIndex":
        return AttackKnowledgeIndex(
            embeddings=self.embeddings.to(device),
            position_targets=self.position_targets.to(device),
            progress=self.progress.to(device),
            knowledge_ids=self.knowledge_ids,
        )


@dataclass(frozen=True)
class M5LossConfig:
    relevance_weight: float = 1.0
    position_weight: float = 1.0
    progress_weight: float = 1.0
    ranking_weight: float = 0.25
    ranking_margin: float = 0.05


class M5KnowledgeProgressTransformer(nn.Module):
    """Local semantic/progress estimator with external-knowledge cross attention.

    Self-attention runs over word/subword token states of the current log only.
    External ATT&CK/attack-chain knowledge is first Top-K retrieved, then used as
    K/V in cross attention. The model jointly outputs:
      1) broad attack relevance probability;
      2) multi-label attack-chain position probabilities;
      3) continuous progress score in [0, 1];
      4) fused semantic embedding for the long-horizon entity-memory linker.

    This module does not itself solve multi-hour/day linking. Long-range recall is
    handled by PersistentEntityMemory and M5EntityProgressLinker.
    """

    def __init__(self, config: M5KnowledgeConfig | None = None) -> None:
        super().__init__()
        self.config = config or M5KnowledgeConfig()
        c = self.config
        self.token_embedding = nn.Embedding(c.vocab_size, c.d_model)
        self.semantic_projection = (
            nn.Linear(c.semantic_input_dim, c.d_model)
            if c.semantic_input_dim is not None and c.semantic_input_dim != c.d_model
            else nn.Identity()
        )
        self.position_embedding = nn.Embedding(c.max_seq_len, c.d_model)
        layer = nn.TransformerEncoderLayer(
            d_model=c.d_model,
            nhead=c.num_heads,
            dim_feedforward=c.feedforward_dim,
            dropout=c.dropout,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.self_encoder = nn.TransformerEncoder(
            layer, num_layers=c.encoder_layers, norm=nn.LayerNorm(c.d_model), enable_nested_tensor=False
        )
        self.retrieval_query = nn.Linear(c.d_model, c.d_model, bias=False)
        self.knowledge_key = nn.Linear(c.d_model, c.d_model, bias=False)
        self.knowledge_value = nn.Linear(c.d_model, c.d_model, bias=False)
        self.cross_attention = nn.MultiheadAttention(c.d_model, c.num_heads, dropout=c.dropout, batch_first=True)
        self.cross_gate = nn.Linear(c.d_model * 2, c.d_model)
        self.cross_norm = nn.LayerNorm(c.d_model)

        head_dim = c.d_model + c.num_positions + 1
        self.relevance_head = nn.Sequential(nn.Linear(head_dim, c.d_model), nn.GELU(), nn.Linear(c.d_model, 1))
        self.position_head = nn.Sequential(nn.Linear(head_dim, c.d_model), nn.GELU(), nn.Linear(c.d_model, c.num_positions))
        self.progress_head = nn.Sequential(nn.Linear(head_dim, c.d_model), nn.GELU(), nn.Linear(c.d_model, 1))
        self.progress_gate = nn.Sequential(nn.Linear(head_dim, 1), nn.Sigmoid())

    @staticmethod
    def _masked_mean(values: Tensor, mask: Tensor) -> Tensor:
        weights = mask.to(values.dtype).unsqueeze(-1)
        return (values * weights).sum(dim=1) / weights.sum(dim=1).clamp_min(1.0)

    def encode_log_tokens(
        self,
        token_ids: Tensor,
        attention_mask: Tensor,
        semantic_token_states: Tensor | None = None,
    ) -> tuple[Tensor, Tensor]:
        if token_ids.ndim != 2 or attention_mask.shape != token_ids.shape:
            raise ValueError("token_ids and attention_mask must have shape [batch, seq_len]")
        batch, seq_len = token_ids.shape
        if seq_len == 0 or seq_len > self.config.max_seq_len:
            raise ValueError("seq_len must be between 1 and max_seq_len")
        if semantic_token_states is None and torch.any((token_ids < 0) | (token_ids >= self.config.vocab_size)):
            raise ValueError("token_ids contain values outside configured vocabulary")
        mask = attention_mask.bool()
        if not torch.all(mask.any(dim=1)):
            raise ValueError("every log must contain at least one unmasked token")
        positions = torch.arange(seq_len, device=token_ids.device).unsqueeze(0).expand(batch, -1)
        if semantic_token_states is None:
            hidden = self.token_embedding(token_ids)
        else:
            expected_dim = self.config.semantic_input_dim or self.config.d_model
            if semantic_token_states.shape != (batch, seq_len, expected_dim):
                raise ValueError(
                    "semantic_token_states must have shape [batch, seq_len, semantic_input_dim]"
                )
            hidden = self.semantic_projection(semantic_token_states.to(dtype=self.position_embedding.weight.dtype))
        hidden = hidden + self.position_embedding(positions)
        hidden = self.self_encoder(hidden, src_key_padding_mask=~mask)
        return hidden, self._masked_mean(hidden, mask)

    def _retrieve(
        self,
        query_pool: Tensor,
        knowledge: AttackKnowledgeIndex,
        allowed_knowledge_mask: Tensor | None,
    ) -> tuple[Tensor, Tensor]:
        c = self.config
        knowledge.validate(c.d_model, c.num_positions)
        if knowledge.embeddings.shape[0] > c.knowledge_candidate_cap:
            raise ValueError(
                "knowledge candidate count exceeds knowledge_candidate_cap; "
                "prefilter the external database (for example with ANN/vector search) before M5"
            )
        knowledge_embeddings = knowledge.embeddings.to(device=query_pool.device, dtype=query_pool.dtype)
        query = F.normalize(self.retrieval_query(query_pool), dim=-1)
        keys = F.normalize(self.knowledge_key(knowledge_embeddings), dim=-1)
        similarity = query @ keys.transpose(0, 1)
        similarity = similarity / c.retrieval_temperature
        if allowed_knowledge_mask is not None:
            if allowed_knowledge_mask.shape != similarity.shape:
                raise ValueError("allowed_knowledge_mask must have shape [batch, knowledge_count]")
            allowed = allowed_knowledge_mask.to(device=similarity.device, dtype=torch.bool)
            if not torch.all(allowed.any(dim=1)):
                raise ValueError("each sample must allow at least one knowledge entry")
            similarity = similarity.masked_fill(~allowed, torch.finfo(similarity.dtype).min)
        if allowed_knowledge_mask is None:
            top_k = min(c.knowledge_top_k, similarity.shape[1])
        else:
            available_per_sample = allowed.sum(dim=1)
            top_k = min(c.knowledge_top_k, int(available_per_sample.min().item()))
        scores, indices = torch.topk(similarity, k=top_k, dim=1)
        return scores, indices

    @staticmethod
    def _gather_rows(table: Tensor, indices: Tensor) -> Tensor:
        flat = indices.reshape(-1)
        return table.index_select(0, flat).reshape(indices.shape[0], indices.shape[1], *table.shape[1:])

    def forward(
        self,
        token_ids: Tensor,
        attention_mask: Tensor,
        knowledge: AttackKnowledgeIndex,
        *,
        allowed_knowledge_mask: Tensor | None = None,
        semantic_token_states: Tensor | None = None,
    ) -> dict[str, Tensor]:
        c = self.config
        token_hidden, token_pool = self.encode_log_tokens(
            token_ids, attention_mask, semantic_token_states=semantic_token_states
        )
        retrieved_scores, retrieved_indices = self._retrieve(token_pool, knowledge, allowed_knowledge_mask)

        knowledge_embeddings = knowledge.embeddings.to(device=token_hidden.device, dtype=token_hidden.dtype)
        knowledge_positions = knowledge.position_targets.to(device=token_hidden.device, dtype=token_hidden.dtype)
        knowledge_progress = knowledge.progress.to(device=token_hidden.device, dtype=token_hidden.dtype)
        selected_embeddings = self._gather_rows(knowledge_embeddings, retrieved_indices)
        selected_positions = self._gather_rows(knowledge_positions, retrieved_indices)
        selected_progress = self._gather_rows(knowledge_progress, retrieved_indices)

        knowledge_keys = self.knowledge_key(selected_embeddings)
        knowledge_values = self.knowledge_value(selected_embeddings)
        cross_hidden, _ = self.cross_attention(token_hidden, knowledge_keys, knowledge_values, need_weights=False)
        gate = torch.sigmoid(self.cross_gate(torch.cat([token_hidden, cross_hidden], dim=-1)))
        fused_tokens = self.cross_norm(token_hidden + gate * cross_hidden)
        fused_pool = self._masked_mean(fused_tokens, attention_mask.bool())

        retrieval_weights = torch.softmax(retrieved_scores, dim=-1)
        position_prior = (selected_positions * retrieval_weights.unsqueeze(-1)).sum(dim=1)
        progress_prior = (selected_progress * retrieval_weights).sum(dim=1)
        head_input = torch.cat([fused_pool, position_prior, progress_prior.unsqueeze(-1)], dim=-1)

        relevance_logit = self.relevance_head(head_input).squeeze(-1)
        position_logits = self.position_head(head_input)
        learned_progress = torch.sigmoid(self.progress_head(head_input).squeeze(-1))
        progress_gate = self.progress_gate(head_input).squeeze(-1)
        progress_score = progress_gate * learned_progress + (1.0 - progress_gate) * progress_prior
        relevance_probability = torch.sigmoid(relevance_logit)
        position_probabilities = torch.sigmoid(position_logits)

        return {
            "semantic_embedding": fused_pool,
            "relevance_logit": relevance_logit,
            "relevance_probability": relevance_probability,
            "attack_candidate": relevance_probability >= c.broad_attack_threshold,
            "position_logits": position_logits,
            "position_probabilities": position_probabilities,
            "progress_score": progress_score.clamp(0.0, 1.0),
            "learned_progress": learned_progress,
            "knowledge_progress_prior": progress_prior,
            "knowledge_position_prior": position_prior,
            "retrieved_indices": retrieved_indices,
            "retrieved_scores": retrieved_scores,
        }


def progress_target_from_attack_step(step_index: int, total_steps: int) -> float:
    """Map a 1-based annotated attack step to a continuous progress target."""
    if total_steps <= 0:
        raise ValueError("total_steps must be positive")
    if step_index <= 0 or step_index > total_steps:
        raise ValueError("step_index must be in [1, total_steps]")
    return float(step_index) / float(total_steps)


def multilabel_position_target(position_indices: Sequence[int], num_positions: int) -> Tensor:
    if num_positions <= 0:
        raise ValueError("num_positions must be positive")
    target = torch.zeros(num_positions, dtype=torch.float32)
    for index in position_indices:
        if not 0 <= int(index) < num_positions:
            raise ValueError("position index out of range")
        target[int(index)] = 1.0
    return target


def pairwise_progress_ranking_loss(progress_score: Tensor, ranking_pairs: Tensor | None, margin: float = 0.05) -> Tensor:
    """Pairs are [earlier_index, later_index] within the current batch."""
    if ranking_pairs is None or ranking_pairs.numel() == 0:
        return progress_score.new_zeros(())
    if ranking_pairs.ndim != 2 or ranking_pairs.shape[1] != 2:
        raise ValueError("ranking_pairs must have shape [pair_count, 2]")
    pairs = ranking_pairs.to(device=progress_score.device, dtype=torch.long)
    if torch.any((pairs < 0) | (pairs >= progress_score.shape[0])):
        raise ValueError("ranking pair index out of range")
    earlier = progress_score.index_select(0, pairs[:, 0])
    later = progress_score.index_select(0, pairs[:, 1])
    return F.relu(margin - (later - earlier)).mean()


def m5_multitask_loss(
    output: dict[str, Tensor],
    *,
    attack_targets: Tensor,
    position_targets: Tensor,
    progress_targets: Tensor,
    progress_mask: Tensor | None = None,
    ranking_pairs: Tensor | None = None,
    config: M5LossConfig | None = None,
) -> dict[str, Tensor]:
    cfg = config or M5LossConfig()
    relevance_logit = output["relevance_logit"]
    position_logits = output["position_logits"]
    progress_score = output["progress_score"]
    if attack_targets.shape != relevance_logit.shape:
        raise ValueError("attack_targets shape must match relevance output")
    if position_targets.shape != position_logits.shape:
        raise ValueError("position_targets shape must match position output")
    if progress_targets.shape != progress_score.shape:
        raise ValueError("progress_targets shape must match progress output")

    attack_targets = attack_targets.to(device=relevance_logit.device, dtype=relevance_logit.dtype)
    position_targets = position_targets.to(device=position_logits.device, dtype=position_logits.dtype)
    progress_targets = progress_targets.to(device=progress_score.device, dtype=progress_score.dtype)
    if progress_mask is None:
        progress_mask = attack_targets > 0.5
    else:
        progress_mask = progress_mask.to(device=progress_score.device, dtype=torch.bool)
        if progress_mask.shape != progress_score.shape:
            raise ValueError("progress_mask shape must match progress output")

    relevance_loss = F.binary_cross_entropy_with_logits(relevance_logit, attack_targets)
    position_loss = F.binary_cross_entropy_with_logits(position_logits, position_targets)
    if progress_mask.any():
        progress_loss = F.smooth_l1_loss(progress_score[progress_mask], progress_targets[progress_mask])
    else:
        progress_loss = progress_score.new_zeros(())
    ranking_loss = pairwise_progress_ranking_loss(progress_score, ranking_pairs, cfg.ranking_margin)
    total = (
        cfg.relevance_weight * relevance_loss
        + cfg.position_weight * position_loss
        + cfg.progress_weight * progress_loss
        + cfg.ranking_weight * ranking_loss
    )
    return {
        "loss": total,
        "relevance_loss": relevance_loss,
        "position_loss": position_loss,
        "progress_loss": progress_loss,
        "ranking_loss": ranking_loss,
    }
