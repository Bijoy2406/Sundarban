"""Audit log (Person 2 owns). STUB for now.

Real version: append-only JSONL, each line stores the hash of the previous line,
verify() recomputes the chain.
"""

_EVENTS: list = []


def log(event: dict) -> None:
    """STUB: keeps events in memory only."""
    _EVENTS.append(dict(event))


def verify(path: str = "") -> bool:
    """STUB: always True."""
    return True
