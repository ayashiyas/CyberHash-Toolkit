import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import identifier


def test_identify_md5_length():
    results = identifier.identify("900150983cd24fb0d6963f7d28e17f72")
    names = [r["algorithm"] for r in results]
    assert "MD5" in names
    assert results[0]["algorithm"] == "MD5"  # boosted to top


def test_identify_sha256_length():
    results = identifier.identify("a" * 64)
    names = [r["algorithm"] for r in results]
    assert "SHA-256" in names


def test_identify_bcrypt_prefix():
    results = identifier.identify("$2b$12$abcdefghijklmnopqrstuv")
    assert results[0]["algorithm"] == "bcrypt"
    assert results[0]["confidence"] == 95


def test_identify_empty_string():
    assert identifier.identify("") == []


def test_identify_unrecognized():
    results = identifier.identify("not a hash!!")
    assert results[0]["algorithm"] == "Unrecognized format"
