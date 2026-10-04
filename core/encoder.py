"""
core.encoder
Base64, hex, URL, and ROT13 encode/decode helpers.
"""

import base64
import codecs
import urllib.parse


def base64_encode(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def base64_decode(text):
    return base64.b64decode(text.encode("ascii")).decode("utf-8", errors="replace")


def hex_encode(text):
    return text.encode("utf-8").hex()


def hex_decode(text):
    return bytes.fromhex(text).decode("utf-8", errors="replace")


def url_encode(text):
    return urllib.parse.quote(text, safe="")


def url_decode(text):
    return urllib.parse.unquote(text)


def rot13(text):
    return codecs.encode(text, "rot_13")


# name -> (encode_fn, decode_fn or None if symmetric)
TOOLS = {
    "base64": (base64_encode, base64_decode),
    "hex": (hex_encode, hex_decode),
    "url": (url_encode, url_decode),
    "rot13": (rot13, rot13),  # ROT13 is its own inverse
}


def run(tool, mode, text):
    """tool in TOOLS keys, mode 'encode' or 'decode'."""
    tool = tool.lower()
    if tool not in TOOLS:
        raise ValueError(f"Unknown tool: {tool}")
    encode_fn, decode_fn = TOOLS[tool]
    if mode == "encode":
        return encode_fn(text)
    if mode == "decode":
        return decode_fn(text)
    raise ValueError("mode must be 'encode' or 'decode'")
