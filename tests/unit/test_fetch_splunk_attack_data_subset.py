from scripts.fetch_splunk_attack_data_subset import is_lfs_pointer


def test_lfs_pointer_is_never_accepted_as_raw_log():
    pointer = b"version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 12\n"
    assert is_lfs_pointer(pointer)
    assert not is_lfs_pointer(b'{"EventID": 1}\n')
