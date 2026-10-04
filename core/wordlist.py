"""
core.wordlist
Load word candidates for the educational wordlist-attack module.
"""

import os

DEFAULT_WORDLIST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "wordlist.txt"
)


def load(path=None, limit=None):
    """
    Load a wordlist file, one word per line. Blank lines and lines
    starting with '#' are skipped. `limit` bounds how many words load,
    to keep demo attacks fast and finite.
    """
    path = path or DEFAULT_WORDLIST
    words = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if not word or word.startswith("#"):
                continue
            words.append(word)
            if limit and len(words) >= limit:
                break
    return words
