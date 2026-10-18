"""Approval tokens (Person 2 owns): HMAC-SHA256 proof that the firewall approved ONE exact transaction.

A token looks like  "<expiry_unix_seconds>.<hex_hmac>".
The HMAC covers: request_id, action, token address, recipient/spender, amount and the expiry.
Change any one of them (or the expiry) and verification fails.

The secret comes from APPROVAL_SECRET in .env. It is never logged or returned.

Two extra protections (hardening):
  * ONE USE ONLY: a token that verified once is remembered and refused the second time, so a token
    cannot be replayed to send the same transfer again within its lifetime.
  * KILL SWITCH: while the kill switch is on, every token (even one issued a moment ago) is refused.
"""
import hashlib
import hmac
import json
import os
import threading
import time

from . import state

STUB_TOKEN = "STUB-TOKEN"   # kept only so old code still imports; it is NOT accepted

MIN_SECRET_LENGTH = 16

_USED = {}                  # signature (the part after the dot) -> its expiry time (kept only until it expires)
_USED_LOCK = threading.Lock()


def reset() -> None:
    """Forget which tokens were used (used by tests)."""
    with _USED_LOCK:
        _USED.clear()


def _secret() -> bytes:
    secret = os.getenv("APPROVAL_SECRET", "")
    if len(secret) < MIN_SECRET_LENGTH:
        raise RuntimeError(f"APPROVAL_SECRET is missing or shorter than {MIN_SECRET_LENGTH} characters (set it in .env)")
    return secret.encode("utf-8")


def _sign(request_id: str, action: str, token: str, to: str, amount: str, expiry: int) -> str:
    # JSON list = unambiguous encoding (no way to shift a character from one field into the next).
    message = json.dumps(
        [str(request_id), str(action), str(token).lower(), str(to).lower(), str(amount), int(expiry)],
        separators=(",", ":"),
    )
    return hmac.new(_secret(), message.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_token(request_id: str, action: str, token: str, to: str, amount: str, ttl_seconds: int = 120) -> str:
    """Create an approval token for exactly this transaction, valid for ttl_seconds."""
    expiry = int(time.time()) + int(ttl_seconds)
    return f"{expiry}.{_sign(request_id, action, token, to, amount, expiry)}"


def verify_token(approval_token: str, request_id: str, action: str, token_addr: str, to: str, amount: str) -> bool:
    """True only if the token is genuine, unexpired, matches every field, was not used before and the
    kill switch is off. Using it counts as its one use. Never raises: any problem -> False."""
    try:
        if state.kill_switch_on():
            return False
        if not isinstance(approval_token, str):
            return False
        expiry_text, _, given_mac = approval_token.partition(".")
        expiry = int(expiry_text)
        if str(expiry) != expiry_text:          # canonical digits only: int() also accepts "+1", " 1", "01", "1_0"
            return False
        now = time.time()
        if now > expiry:
            return False
        expected_mac = _sign(request_id, action, token_addr, to, amount, expiry)
        if not hmac.compare_digest(given_mac.encode("utf-8"), expected_mac.encode("utf-8")):
            return False
        with _USED_LOCK:
            for old in [t for t, exp in _USED.items() if exp < now]:   # forget expired ones
                del _USED[old]
            if given_mac in _USED:                 # keyed by the signature itself, never by how the token was spelled
                return False
            _USED[given_mac] = expiry
        return True
    except Exception:
        return False