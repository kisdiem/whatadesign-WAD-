from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StageSpec:
    stage_name: str
    input_contract: tuple[str, ...]
    output_contract: tuple[str, ...]
    config_section: str
    required_checkpoints: tuple[str, ...] = ()
    execution_modes: tuple[str, ...] = ("synthetic", "source")


class StageRegistry:
    def __init__(self, specs: tuple[StageSpec, ...] | None = None):
        self._specs = {spec.stage_name: spec for spec in (specs or default_stage_specs())}

    def get(self, name: str) -> StageSpec:
        return self._specs[name]

    def names(self) -> tuple[str, ...]:
        return tuple(self._specs)


def default_stage_specs() -> tuple[StageSpec, ...]:
    names = ("ingest", "split", "m0_fit", "m0_transform", "m1_train", "m1_infer", "m2_resolve", "m3_train", "m3_encode", "m3_causal", "m4_train", "m4_infer", "m5_build", "m5_train", "m5_infer", "frozen_export", "m6_train", "source_calibration", "source_evaluation", "release_preflight")
    return tuple(StageSpec(name, ("previous_stage_artifact",), (f"{name}_manifest.json",), name) for name in names)
