"""Approval tokens (Person 2 owns): HMAC-SHA256 proof that the firewall approved ONE exact transaction.

A token looks like  "<expiry_unix_seconds>.<hex_hmac>".
The HMAC covers: request_id, action, token address, recipient/spender, amount and the expiry.
Change any one of them (or the expiry) and verification fails.

The secret comes from APPROVAL_SECRET in .env. It is never logged or returned.

Two extra protections (hardening):
  * ONE USE ONLY: a token that verified once is remembered (in a small file, flushed to disk, so a restart does
    not forget it) and refused the second time, so a token cannot be replayed to send the same transfer again.
  * KILL SWITCH: while the kill switch is on, every token (even one issued a moment ago) is refused.
"""
import hashlib
import hmac
import json
import os
import re
import threading
import time
from pathlib import Path

from . import state

STUB_TOKEN = "STUB-TOKEN"   # kept only so old code still imports; it is NOT accepted

MIN_SECRET_LENGTH = 16

_USED = {}                  # in-process mirror: signature (the part after the dot) -> expiry. The FILE is what is checked.
_USED_LOCK = threading.Lock()
_SIGNATURE = re.compile(r"[0-9a-f]{64}")


def _used_path() -> Path:
    """Where spent signatures are remembered across restarts (env USED_TOKENS_PATH, default logs/used_tokens.jsonl)."""
    env = os.getenv("USED_TOKENS_PATH")
    return Path(env) if env else state.LOGS_DIR / "used_tokens.jsonl"


def _load_used() -> list:
    """[(signature, expiry), ...] from the file. A missing file is empty; anything unreadable RAISES (fail closed)."""
    path = _used_path()
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return []
    if not data:
        return []
    if not data.endswith(b"\n"):
        raise ValueError("the used-token record ends in a half-written line")
    entries = []
    for line in data.split(b"\n")[:-1]:
        item = json.loads(line.decode("utf-8"))
        sig, exp = item["sig"], item["exp"]
        if set(item) != {"sig", "exp"} or not isinstance(sig, str) or not _SIGNATURE.fullmatch(sig) \
                or type(exp) is not int:
            raise ValueError("the used-token record is damaged")
        entries.append((sig, exp))
    return entries


def _entry(sig: str, expiry: int) -> bytes:
    return json.dumps({"sig": sig, "exp": int(expiry)}, separators=(",", ":")).encode("utf-8") + b"\n"


def reset() -> None:
    """Forget which tokens were used (tests, and the red-team runner between cases). The file is only removed when
    USED_TOKENS_PATH is set explicitly: the real logs/ folder is never touched by accident."""
    with _USED_LOCK:
        _USED.clear()
        if os.getenv("USED_TOKENS_PATH"):
            _used_path().unlink(missing_ok=True)


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
            entries = _load_used()                 # unreadable -> an exception -> False: never accept on a doubt
            if given_mac in _USED or any(sig == given_mac for sig, _ in entries):
                return False                       # keyed by the signature itself, never by how the token was spelled
            live = [(sig, exp) for sig, exp in entries if exp >= now]     # expired entries are dropped while writing
            path = _used_path()
            if len(live) == len(entries):
                state._append_durable(path, _entry(given_mac, expiry))
            else:
                state._write_atomic(path, [_entry(sig, exp) for sig, exp in live] + [_entry(given_mac, expiry)])
            _USED[given_mac] = expiry              # remembered on disk first; only then does the token count as used
        return True
    except Exception:
        return False