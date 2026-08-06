import torch

def masked_node_loss(logits, targets, mask=None):
    loss = torch.nn.functional.cross_entropy(logits, targets, reduction="none")
    return loss[mask].mean() if mask is not None and mask.any() else loss.mean()

def neighborhood_contrastive_loss(left, right, temperature=0.1):
    return 1 - torch.nn.functional.cosine_similarity(left, right, dim=-1).mean()
