"""
core.identifier
Guess which algorithm produced a given hash string.
Heuristic only: length + charset + known prefixes. Not authoritative -
many algorithms share output length, so results are confidence-ranked,
not certain.
"""

import re

HEX_RE = re.compile(r"^[a-fA-F0-9]+$")

# hex-digest length (chars) -> candidate algorithms
LENGTH_MAP = {
    8: ["CRC32"],
    32: ["MD5", "NTLM", "MD4"],
    40: ["SHA-1", "RIPEMD-160"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"],
}

# known salted/crypt-style prefixes -> algorithm
PREFIX_MAP = {
    "$1$": "MD5 crypt",
    "$2a$": "bcrypt",
    "$2b$": "bcrypt",
    "$2y$": "bcrypt",
    "$5$": "SHA-256 crypt",
    "$6$": "SHA-512 crypt",
    "$argon2i$": "Argon2i",
    "$argon2id$": "Argon2id",
}


def identify(value):
    """
    Identify possible algorithms for a hash string.
    Returns list of dicts: {"algorithm": name, "confidence": 0-100}
    sorted by confidence descending.
    """
    value = value.strip()
    if not value:
        return []

    # 1. Known prefix formats (bcrypt, crypt, argon2)
    for prefix, name in PREFIX_MAP.items():
        if value.startswith(prefix):
            return [{"algorithm": name, "confidence": 95}]

    # 2. Plain hex digest - match by length
    if HEX_RE.match(value):
        candidates = LENGTH_MAP.get(len(value))
        if candidates:
            confidence = round(100 / len(candidates))
            # Most common algorithm per length gets a small boost
            boosted = {
                32: "MD5",
                40: "SHA-1",
                64: "SHA-256",
                128: "SHA-512",
            }.get(len(value))
            results = []
            for algo in candidates:
                conf = confidence + (10 if algo == boosted else 0)
                results.append({"algorithm": algo, "confidence": min(conf, 99)})
            results.sort(key=lambda r: r["confidence"], reverse=True)
            return results
        return [{"algorithm": f"Unknown hex ({len(value)} chars)", "confidence": 10}]

    # 3. Base64-looking value (common for SHA-256/512 stored as base64)
    b64_re = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
    if b64_re.match(value) and len(value) % 4 == 0:
        return [{"algorithm": "Possible Base64-encoded hash", "confidence": 40}]

    return [{"algorithm": "Unrecognized format", "confidence": 0}]
