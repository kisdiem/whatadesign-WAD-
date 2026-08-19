from scripts.train_attack_technique_adapter import stable_group_split


def test_source_group_split_never_splits_a_file_between_partitions():
    groups = {"a": "file-one", "b": "file-one", "c": "file-two", "d": "file-three"}
    train, validation = stable_group_split(groups, 0.34)
    assert train
    assert validation
    for first, second in (("a", "b"),):
        assert (first in train) == (second in train)
        assert (first in validation) == (second in validation)
