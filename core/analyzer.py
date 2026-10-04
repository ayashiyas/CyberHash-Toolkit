"""
core.analyzer
Hash comparison, dictionary-based decoding, and a deliberately bounded
brute-force demo. These exist to teach *why* unsalted fast hashes are
weak against wordlists/brute-force, not to serve as a real cracking tool:
limits below are hard caps, not just defaults.
"""

import itertools

from . import hasher, wordlist as wl_module

# Hard safety caps - keep the "demonstration" a demonstration.
MAX_BRUTEFORCE_LENGTH = 5
MAX_BRUTEFORCE_CHARSET = 40
MAX_BRUTEFORCE_ATTEMPTS = 2_000_000
MAX_WORDLIST_WORDS = 50_000


def compare_hashes(hash_a, hash_b):
    """Case-insensitive comparison of two hash strings."""
    return hash_a.strip().lower() == hash_b.strip().lower()


def decode_hash(target_hash, algorithm, wordlist_path=None, limit=MAX_WORDLIST_WORDS):
    """
    Try to recover plaintext for target_hash using the bundled/small
    wordlist. Thin wrapper around wordlist_attack kept as a separate,
    friendlier entry point ('Hash decoder' in the menu).
    """
    return wordlist_attack(target_hash, algorithm, wordlist_path, limit)


def wordlist_attack(target_hash, algorithm, wordlist_path=None, limit=MAX_WORDLIST_WORDS):
    """
    Hash each word in a wordlist file and compare to target_hash.
    Returns dict: {"found": bool, "plaintext": str|None, "attempts": int}
    """
    limit = min(limit, MAX_WORDLIST_WORDS)
    words = wl_module.load(wordlist_path, limit=limit)
    return attack_words(target_hash, algorithm, words)


def attack_words(target_hash, algorithm, words, limit=MAX_WORDLIST_WORDS):
    """
    Same as wordlist_attack but takes an in-memory word list directly
    (used by the web UI, where words come from a pasted textarea).
    """
    target_hash = target_hash.strip().lower()
    limit = min(limit, MAX_WORDLIST_WORDS)
    attempts = 0
    for word in words[:limit]:
        attempts += 1
        candidate = hasher.hash_text(word, algorithm)
        if candidate.lower() == target_hash:
            return {"found": True, "plaintext": word, "attempts": attempts}
    return {"found": False, "plaintext": None, "attempts": attempts}


def bounded_bruteforce(target_hash, algorithm, charset, max_length):
    """
    Try every combination of `charset` up to `max_length` characters.
    Hard-capped so this stays an educational demo of keyspace growth,
    not a usable cracking tool: short charset, short length, attempt ceiling.
    Returns dict: {"found", "plaintext", "attempts", "capped"}
    """
    if max_length > MAX_BRUTEFORCE_LENGTH:
        raise ValueError(f"max_length capped at {MAX_BRUTEFORCE_LENGTH} for this demo")
    if len(charset) > MAX_BRUTEFORCE_CHARSET:
        raise ValueError(f"charset capped at {MAX_BRUTEFORCE_CHARSET} characters")

    target_hash = target_hash.strip().lower()
    attempts = 0
    capped = False

    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            attempts += 1
            if attempts > MAX_BRUTEFORCE_ATTEMPTS:
                capped = True
                return {"found": False, "plaintext": None, "attempts": attempts, "capped": capped}
            candidate_text = "".join(combo)
            candidate_hash = hasher.hash_text(candidate_text, algorithm)
            if candidate_hash.lower() == target_hash:
                return {"found": True, "plaintext": candidate_text, "attempts": attempts, "capped": capped}

    return {"found": False, "plaintext": None, "attempts": attempts, "capped": capped}


def keyspace_size(charset_len, max_length):
    """Total number of candidates a brute-force over 1..max_length would try."""
    return sum(charset_len ** n for n in range(1, max_length + 1))
