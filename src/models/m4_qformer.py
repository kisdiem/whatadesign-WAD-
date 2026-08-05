from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor, nn


@dataclass(frozen=True)
class M4Config:
    input_dim: int = 128
    hidden_dim: int = 128
    query_count: int = 8
    heads: int = 4
    layers: int = 2
    dropout: float = 0.1
    version: str = "m4_qformer_decoder_v1"


class M4QFormerDecoder(nn.Module):
    """Query-token sequence encoder with a compact anomaly decoder.

    The module accepts source-domain event features only. Target labels and
    knowledge-base labels are intentionally outside this interface.
    """

    def __init__(self, config: M4Config | None = None) -> None:
        super().__init__()
        self.config = config or M4Config()
        c = self.config
        self.input_projection = nn.Linear(c.input_dim, c.hidden_dim)
        self.query_tokens = nn.Parameter(torch.randn(c.query_count, c.hidden_dim) * 0.02)
        self.query_attention = nn.MultiheadAttention(c.hidden_dim, c.heads, dropout=c.dropout, batch_first=True)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=c.hidden_dim, nhead=c.heads, dim_feedforward=c.hidden_dim * 4,
            dropout=c.dropout, batch_first=True, norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=c.layers)
        self.decoder = nn.Sequential(nn.LayerNorm(c.hidden_dim), nn.Linear(c.hidden_dim, 1))

    def forward(self, sequence: Tensor, padding_mask: Tensor | None = None) -> dict[str, Tensor]:
        if sequence.ndim != 3 or sequence.shape[-1] != self.config.input_dim:
            raise ValueError("sequence must have shape [batch, time, input_dim]")
        hidden = self.input_projection(sequence)
        hidden = self.encoder(hidden, src_key_padding_mask=padding_mask)
        queries = self.query_tokens.unsqueeze(0).expand(sequence.shape[0], -1, -1)
        attended, _ = self.query_attention(queries, hidden, hidden, key_padding_mask=padding_mask)
        pooled = attended.mean(dim=1)
        return {"embedding": pooled, "score_logit": self.decoder(pooled).squeeze(-1)}
