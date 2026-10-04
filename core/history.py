"""
core.history
Keep recent operations in a local JSON file for quick review while
learning/testing. Nothing leaves the machine.
"""

import json
import os
from datetime import datetime

HISTORY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "history.json"
)
MAX_ENTRIES = 200


def _load():
    if not os.path.exists(HISTORY_PATH):
        return []
    try:
        with open(HISTORY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save(entries):
    os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
    with open(HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def add_entry(operation, detail):
    """Append one entry. operation: short label. detail: dict of specifics."""
    entries = _load()
    entries.append({
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "operation": operation,
        "detail": detail,
    })
    entries = entries[-MAX_ENTRIES:]  # keep bounded
    _save(entries)


def get_history(limit=20):
    """Return the most recent `limit` entries, newest first."""
    entries = _load()
    return list(reversed(entries))[:limit]


def clear_history():
    _save([])
