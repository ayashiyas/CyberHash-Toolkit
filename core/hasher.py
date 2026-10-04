"""
core.hasher
Text and file hashing across 10 algorithms. Stdlib hashlib only, no deps.
"""

import hashlib

# 10 supported algorithms, name -> hashlib constructor
ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}

# Security posture per algorithm, used to warn users in the UI/CLI.
# status: "broken" (collisions found, never use for security), "weak"
# (deprecated, avoid), "secure" (fine for integrity/security use today).
ALGO_INFO = {
    "md5":      {"status": "broken", "note": "Collision attacks are practical. Integrity-check use only, never for passwords/signatures."},
    "sha1":     {"status": "broken", "note": "Collisions demonstrated (SHAttered, 2017). Deprecated everywhere."},
    "sha224":   {"status": "secure", "note": "SHA-2 family, shorter output. Fine, but SHA-256 is more common."},
    "sha256":   {"status": "secure", "note": "Industry standard. Good default for integrity checks."},
    "sha384":   {"status": "secure", "note": "SHA-2 family, larger output than SHA-256."},
    "sha512":   {"status": "secure", "note": "SHA-2 family, largest common output size."},
    "sha3_256": {"status": "secure", "note": "Different internal design (Keccak) from SHA-2, good hedge against future SHA-2 breaks."},
    "sha3_512": {"status": "secure", "note": "SHA-3 family, largest output."},
    "blake2b":  {"status": "secure", "note": "Fast, modern, used in many current protocols (e.g. WireGuard)."},
    "blake2s":  {"status": "secure", "note": "BLAKE2 variant tuned for 32-bit/small platforms."},
}

CHUNK_SIZE = 65536  # 64KB read chunks for file hashing


def list_algorithms():
    """Return sorted list of supported algorithm names."""
    return sorted(ALGORITHMS.keys())


def hash_text(text, algorithm):
    """Hash a text string with given algorithm. Return hex digest."""
    algorithm = algorithm.lower()
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    h = ALGORITHMS[algorithm]()
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def hash_text_all(text):
    """Hash text with every supported algorithm. Return dict algo -> hexdigest."""
    return {algo: hash_text(text, algo) for algo in ALGORITHMS}


def hash_file(path, algorithm):
    """Hash file contents with given algorithm, streamed. Return hex digest."""
    algorithm = algorithm.lower()
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    h = ALGORITHMS[algorithm]()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_file_all(path):
    """Hash file with every supported algorithm. Return dict algo -> hexdigest."""
    return {algo: hash_file(path, algo) for algo in ALGORITHMS}
