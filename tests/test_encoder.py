import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import encoder


def test_base64_roundtrip():
    assert encoder.base64_decode(encoder.base64_encode("hello world")) == "hello world"


def test_hex_roundtrip():
    assert encoder.hex_decode(encoder.hex_encode("hello")) == "hello"


def test_url_roundtrip():
    text = "a b/c?d=e"
    assert encoder.url_decode(encoder.url_encode(text)) == text


def test_rot13_self_inverse():
    text = "The Quick Brown Fox"
    assert encoder.rot13(encoder.rot13(text)) == text


def test_run_dispatch():
    assert encoder.run("base64", "encode", "hi") == encoder.base64_encode("hi")


def test_run_unknown_tool_raises():
    try:
        encoder.run("nope", "encode", "hi")
        assert False, "expected ValueError"
    except ValueError:
        pass
