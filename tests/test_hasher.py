import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import hasher


def test_list_algorithms_count():
    assert len(hasher.list_algorithms()) == 10


def test_md5_known_vector():
    assert hasher.hash_text("abc", "md5") == "900150983cd24fb0d6963f7d28e17f72"


def test_sha256_known_vector():
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert hasher.hash_text("abc", "sha256") == expected


def test_unsupported_algorithm_raises():
    try:
        hasher.hash_text("abc", "notreal")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_hash_text_all_covers_all_algorithms():
    results = hasher.hash_text_all("abc")
    assert set(results.keys()) == set(hasher.list_algorithms())


def test_hash_file(tmp_path):
    p = tmp_path / "sample.txt"
    p.write_text("abc")
    assert hasher.hash_file(str(p), "md5") == hasher.hash_text("abc", "md5")
