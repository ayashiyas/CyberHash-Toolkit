import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from api.index import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_index_page_loads(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"CyberHash" in r.data


def test_health(client):
    r = client.get("/api/health")
    data = r.get_json()
    assert data["status"] == "ok"
    assert len(data["algorithms"]) == 10


def test_hash_text(client):
    r = client.post("/api/hash-text", json={"text": "abc", "algorithm": "sha256"})
    data = r.get_json()
    assert data["digest"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hash_text_all(client):
    r = client.post("/api/hash-text", json={"text": "abc", "algorithm": "all"})
    data = r.get_json()
    assert len(data["results"]) == 10


def test_hash_text_bad_algorithm(client):
    r = client.post("/api/hash-text", json={"text": "abc", "algorithm": "nope"})
    assert r.status_code == 400


def test_identify(client):
    r = client.post("/api/identify", json={"value": "900150983cd24fb0d6963f7d28e17f72"})
    data = r.get_json()
    assert data["results"][0]["algorithm"] == "MD5"


def test_compare_match(client):
    r = client.post("/api/compare", json={"a": "ABC", "b": "abc"})
    assert r.get_json()["match"] is True


def test_compare_no_match(client):
    r = client.post("/api/compare", json={"a": "abc", "b": "xyz"})
    assert r.get_json()["match"] is False


def test_decode_found(client):
    md5_password = "5f4dcc3b5aa765d61d8327deb882cf99"  # md5("password")
    r = client.post("/api/decode", json={"hash": md5_password, "algorithm": "md5"})
    data = r.get_json()
    assert data["found"] is True
    assert data["plaintext"] == "password"


def test_wordlist_attack_custom_words(client):
    md5_password = "5f4dcc3b5aa765d61d8327deb882cf99"
    r = client.post("/api/wordlist", json={"hash": md5_password, "algorithm": "md5", "words": "foo\npassword\nbar"})
    data = r.get_json()
    assert data["found"] is True


def test_bruteforce_small(client):
    md5_abc = "900150983cd24fb0d6963f7d28e17f72"  # md5("abc")
    r = client.post("/api/bruteforce", json={"hash": md5_abc, "algorithm": "md5", "charset": "abc", "max_length": 3})
    data = r.get_json()
    assert data["found"] is True
    assert data["plaintext"] == "abc"


def test_encode_base64(client):
    r = client.post("/api/encode", json={"tool": "base64", "mode": "encode", "text": "hi"})
    assert r.get_json()["result"] == "aGk="
