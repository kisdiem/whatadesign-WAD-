from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor, nn

from src.common.schema import EventFrame, FrozenFeatureRecord


@dataclass(frozen=True)
class M4Config:
    input_dim: int = 128
    hidden_dim: int = 128
    query_count: int = 8
    slot_count: int = 8
    slot_vocab_size: int = 256
    heads: int = 4
    layers: int = 2
    dropout: float = 0.1
    backbone_name: str = "Qwen/Qwen3-0.6B-Base"
    qwen_hidden_dim: int = 1024
    version: str = "m4_multiscale_current_event_v3"


@dataclass(frozen=True)
class M4TemporalConfig:
    """Causal M4 window configuration; window count is intentionally dynamic."""

    macro_seconds: int = 1800
    micro_seconds: int = 300
    stride_seconds: int = 150
    max_micro_windows: int | None = None

    def __post_init__(self) -> None:
        if not (self.macro_seconds >= self.micro_seconds > 0):
            raise ValueError("macro_seconds >= micro_seconds > 0 is required")
        if not (0 < self.stride_seconds <= self.micro_seconds):
            raise ValueError("0 < stride_seconds <= micro_seconds is required")


class MacroWindowAggregator(nn.Module):
    """Temporal association of micro contexts, not a sum of overlapping scores."""

    def __init__(self, hidden_dim: int, heads: int, layers: int, dropout: float) -> None:
        super().__init__()
        self.encoder = nn.TransformerEncoder(
            nn.TransformerEncoderLayer(hidden_dim, heads, hidden_dim * 4, dropout, batch_first=True, norm_first=True),
            num_layers=layers,
        )
        self.current_projection = nn.Linear(hidden_dim, hidden_dim)
        self.attention = nn.MultiheadAttention(hidden_dim, heads, dropout=dropout, batch_first=True)

    def forward(self, micro_contexts: Tensor, current: Tensor, valid_mask: Tensor | None = None) -> dict[str, Tensor]:
        if micro_contexts.ndim != 3 or current.ndim != 2:
            raise ValueError("micro_contexts=[batch,windows,hidden], current=[batch,hidden]")
        if micro_contexts.shape[0] != current.shape[0] or micro_contexts.shape[-1] != current.shape[-1]:
            raise ValueError("macro context/current dimensions do not match")
        batch, windows, _ = micro_contexts.shape
        if windows == 0:
            empty = micro_contexts.new_zeros((batch, current.shape[-1]))
            return {"macro_context_embedding": empty, "macro_attention": micro_contexts.new_zeros((batch, 0))}
        padding = None if valid_mask is None else ~valid_mask.bool()
        encoded = self.encoder(micro_contexts, src_key_padding_mask=padding)
        query = self.current_projection(current).unsqueeze(1)
        pooled, weights = self.attention(query, encoded, encoded, key_padding_mask=padding, need_weights=True)
        return {"macro_context_embedding": pooled.squeeze(1), "macro_attention": weights.squeeze(1)}


class EventSerializer:
    """Serialize EventFrame fields without importing target labels."""

    def __init__(self, input_dim: int) -> None:
        self.input_dim = input_dim

    def __call__(self, fields: list[dict[str, object]], device: torch.device | None = None) -> Tensor:
        values = []
        for field in fields:
            raw = "|".join(f"{key}={field[key]}" for key in sorted(field))
            digest = torch.tensor(list(raw.encode("utf-8")), dtype=torch.float32)
            vector = torch.zeros(self.input_dim, dtype=torch.float32)
            if digest.numel():
                vector[: min(self.input_dim, digest.numel())] = digest[: self.input_dim] / 255.0
            values.append(vector)
        result = torch.stack(values) if values else torch.zeros((0, self.input_dim))
        return result.to(device=device) if device is not None else result


class M4QFormerDecoder(nn.Module):
    """Current-event-conditioned two-stage Q-Former.

    The V3 path supplies history_events and graph_before_current_event with the
    current event excluded, then supplies current_event separately.
    """

    def __init__(self, config: M4Config | None = None) -> None:
        super().__init__()
        self.config = config or M4Config()
        c = self.config
        self.input_projection = nn.Linear(c.input_dim, c.hidden_dim)
        self.query_tokens = nn.Parameter(torch.randn(c.query_count, c.hidden_dim) * 0.02)
        self.stage1_attention = nn.MultiheadAttention(c.hidden_dim, c.heads, dropout=c.dropout, batch_first=True)
        self.stage2_attention = nn.MultiheadAttention(c.hidden_dim, c.heads, dropout=c.dropout, batch_first=True)
        self.history_encoder = nn.TransformerEncoder(
            nn.TransformerEncoderLayer(c.hidden_dim, c.heads, c.hidden_dim * 4, c.dropout, batch_first=True, norm_first=True),
            num_layers=c.layers,
        )
        self.current_projection = nn.Linear(c.input_dim, c.hidden_dim)
        self.qwen_projection = nn.Linear(c.qwen_hidden_dim, c.hidden_dim)
        self.slot_context = nn.Linear(c.hidden_dim * 2, c.hidden_dim)
        self.slot_head = nn.Linear(c.hidden_dim, c.slot_count * c.slot_vocab_size)
        self.raw_event_head = nn.Sequential(nn.LayerNorm(c.hidden_dim), nn.Linear(c.hidden_dim, 1))
        self.macro_aggregator = MacroWindowAggregator(c.hidden_dim, c.heads, c.layers, c.dropout)

    def forward(self, history_events: Tensor, current_event: Tensor | None = None,
                graph_before_current_event: Tensor | None = None,
                padding_mask: Tensor | None = None) -> dict[str, Tensor]:
        if current_event is not None and current_event.ndim == 2 and current_event.shape[-1] != self.config.input_dim:
            # Legacy call: forward(sequence, padding_mask).
            padding_mask = current_event.bool()
            current_event = None
        if current_event is None:
            if history_events.ndim != 3 or history_events.shape[1] < 1:
                raise ValueError("history_events must have shape [batch, time, input_dim]")
            current_event = history_events[:, -1, :]
            history_events = history_events[:, :-1, :]
        if history_events.ndim != 3 or current_event.ndim != 2:
            raise ValueError("history_events=[batch,time,input_dim], current_event=[batch,input_dim]")
        if history_events.shape[0] != current_event.shape[0] or history_events.shape[-1] != self.config.input_dim:
            raise ValueError("history and current event dimensions do not match")
        batch = history_events.shape[0]
        if graph_before_current_event is None:
            graph_before_current_event = history_events.new_zeros((batch, 1, self.config.input_dim))
        if graph_before_current_event.ndim != 3 or graph_before_current_event.shape[0] != batch:
            raise ValueError("graph_before_current_event must have shape [batch, graph_nodes, input_dim]")

        history = self.input_projection(history_events)
        if history.shape[1]:
            history = self.history_encoder(history, src_key_padding_mask=padding_mask)
        graph = self.input_projection(graph_before_current_event)
        # The current event conditions queries before either cross-attention.
        # It is not merely concatenated after history has been summarized.
        current = self.current_projection(current_event)
        queries = self.query_tokens.unsqueeze(0).expand(batch, -1, -1) + current.unsqueeze(1)
        stage1, _ = self.stage1_attention(queries, graph, graph)
        stage2_context = torch.cat([history, stage1], dim=1)
        stage2, _ = self.stage2_attention(stage1, stage2_context, stage2_context)
        context = stage2.mean(dim=1)
        joint = torch.tanh(self.slot_context(torch.cat([context, current], dim=-1)))
        slot_logits = self.slot_head(joint).view(batch, self.config.slot_count, self.config.slot_vocab_size)
        raw_event_logit = self.raw_event_head(joint).squeeze(-1)
        return {"context": context, "embedding": joint, "slot_logits": slot_logits,
                "raw_event_logit": raw_event_logit, "score_logit": raw_event_logit}

    def forward_micro_windows(
        self,
        event_embeddings: Tensor,
        qwen_window_embeddings: Tensor,
        current_event: Tensor,
        *,
        event_valid_mask: Tensor | None = None,
        micro_window_mask: Tensor | None = None,
        graph_embeddings: Tensor | None = None,
    ) -> dict[str, Tensor]:
        """Encode variable-count micro windows then causally aggregate them.

        ``event_embeddings`` is M1 output [B,W,E,D], Qwen is [B,W,Q], and
        every window is queried by the same explicit current-event branch.
        ``graph_embeddings`` may add only nodes assigned to the corresponding
        micro window [B,W,G,D]; callers must not repeat a 30-minute graph.
        """
        if event_embeddings.ndim != 4 or qwen_window_embeddings.ndim != 3 or current_event.ndim != 2:
            raise ValueError("event=[B,W,E,D], qwen=[B,W,Q], current=[B,D] required")
        batch, windows, _, event_dim = event_embeddings.shape
        if event_dim != self.config.input_dim or current_event.shape != (batch, event_dim):
            raise ValueError("M1/current embedding dimension does not match M4 config")
        if qwen_window_embeddings.shape[:2] != (batch, windows) or qwen_window_embeddings.shape[-1] != self.config.qwen_hidden_dim:
            raise ValueError("Qwen window tensor dimension does not match M4 config")
        if graph_embeddings is not None and (graph_embeddings.ndim != 4 or graph_embeddings.shape[:2] != (batch, windows) or graph_embeddings.shape[-1] != event_dim):
            raise ValueError("graph_embeddings must be [B,W,G,input_dim]")
        if windows == 0:
            current = self.current_projection(current_event)
            empty = current.new_zeros((batch, 0, self.config.hidden_dim))
            macro = self.macro_aggregator(empty, current, micro_window_mask)
            joint = torch.tanh(self.slot_context(torch.cat([macro["macro_context_embedding"], current], dim=-1)))
            logit = self.raw_event_head(joint).squeeze(-1)
            return {**macro, "micro_context_embeddings": empty, "event_embedding": joint, "embedding": joint, "raw_event_logit": logit, "score_logit": logit, "micro_window_scores": empty.new_zeros((batch, 0)), "macro_window_score": logit}

        events = self.input_projection(event_embeddings)
        qwen = self.qwen_projection(qwen_window_embeddings).unsqueeze(2)
        source = torch.cat([events, qwen], dim=2)
        if graph_embeddings is not None:
            source = torch.cat([source, self.input_projection(graph_embeddings)], dim=2)
        source = source.reshape(batch * windows, source.shape[2], self.config.hidden_dim)
        current = self.current_projection(current_event)
        queries = self.query_tokens.unsqueeze(0).expand(batch * windows, -1, -1)
        queries = queries + current.repeat_interleave(windows, dim=0).unsqueeze(1)
        # The event mask does not mask the Qwen summary token; graph membership
        # is already window-local at construction time.
        source_padding = None
        if event_valid_mask is not None:
            if event_valid_mask.shape != event_embeddings.shape[:3]:
                raise ValueError("event_valid_mask must be [B,W,E]")
            event_padding = ~event_valid_mask.bool()
            tail = source.new_zeros((batch, windows, source.shape[1] - event_padding.shape[-1]), dtype=torch.bool)
            source_padding = torch.cat([event_padding, tail], dim=-1).reshape(batch * windows, -1)
        attended, attention = self.stage1_attention(queries, source, source, key_padding_mask=source_padding, need_weights=True)
        micro = attended.mean(dim=1).reshape(batch, windows, self.config.hidden_dim)
        micro_scores = self.raw_event_head(micro).squeeze(-1)
        macro = self.macro_aggregator(micro, current, micro_window_mask)
        joint = torch.tanh(self.slot_context(torch.cat([macro["macro_context_embedding"], current], dim=-1)))
        logit = self.raw_event_head(joint).squeeze(-1)
        slot_logits = self.slot_head(joint).view(batch, self.config.slot_count, self.config.slot_vocab_size)
        return {
            **macro,
            "micro_context_embeddings": micro,
            "micro_attention": attention.reshape(batch, windows, attention.shape[-2], attention.shape[-1]),
            "micro_window_scores": micro_scores,
            "event_embedding": joint,
            # Compatibility alias consumed by existing M6 runner code.
            "embedding": joint,
            "slot_logits": slot_logits,
            "raw_event_logit": logit,
            "score_logit": logit,
            # This is a learned macro-context score, not a sum of overlap scores.
            "macro_window_score": logit,
        }

    def slot_nll(self, output: dict[str, Tensor], target_slot_ids: Tensor, ignore_index: int = -100) -> Tensor:
        logits = output["slot_logits"]
        if target_slot_ids.shape != logits.shape[:2]:
            raise ValueError("target_slot_ids must have shape [batch, slot_count]")
        return nn.functional.cross_entropy(logits.transpose(1, 2), target_slot_ids.long(), ignore_index=ignore_index)


def freeze_m4_feature(
    frame: EventFrame,
    output: dict[str, Tensor],
    *,
    graph_embedding: Tensor | None = None,
    producer_checkpoint_hashes: dict[str, str] | None = None,
) -> FrozenFeatureRecord:
    """Adapt strict M4 output for M5/M6 without changing their contracts.

    ``micro_window_score`` is the maximum valid micro evidence, explicitly not
    a sum: adjacent windows overlap by design. M5 receives the final M4 event
    embedding and owns only cross-30-minute/hour-level association.
    """
    micro = output.get("micro_window_scores")
    micro_score = float(micro.max().detach().cpu()) if isinstance(micro, Tensor) and micro.numel() else 0.0
    def scalar(name: str) -> float:
        value = output[name]
        return float(value.reshape(-1)[0].detach().cpu())
    event = output["event_embedding"].reshape(-1, output["event_embedding"].shape[-1])[0]
    return FrozenFeatureRecord(
        record_id=frame.record_id,
        dataset_id=frame.dataset_id,
        timestamp=frame.timestamp,
        semantic_embedding=list(frame.semantic_embedding or []),
        graph_embedding=graph_embedding.detach().cpu().flatten().tolist() if graph_embedding is not None else [],
        event_embedding=event.detach().cpu().tolist(),
        raw_event_score=scalar("raw_event_logit"),
        micro_window_score=micro_score,
        macro_window_score=scalar("macro_window_score"),
        long_horizon_score=0.0,
        source_record_ref=frame.source_record_ref,
        producer_checkpoint_hashes=producer_checkpoint_hashes or {},
    )
