import pytest

from scripts.phase_d_release.lock_release import validate_release


def test_lock_validation_requires_real_checkpoint_and_release_inputs(tmp_path):
    assert "checkpoints/*.pt" in validate_release(tmp_path)
    with pytest.raises(Exception):
        from scripts.phase_d_release.lock_release import lock_release
        lock_release(tmp_path)
