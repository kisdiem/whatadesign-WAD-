from src.semantic.m1_multitask import M1DebertaMultiTask


def multitask_loss(model: M1DebertaMultiTask, output, targets):
    return model.loss(output, targets)

__all__ = ["multitask_loss"]
