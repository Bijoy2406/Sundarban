"""Approval tokens (Person 2 owns): HMAC-SHA256 proof that the firewall approved ONE exact transaction.

A token looks like  "<expiry_unix_seconds>.<hex_hmac>".
The HMAC covers: request_id, action, token address, recipient/spender, amount and the expiry.
Change any one of them (or the expiry) and verification fails.

The secret comes from APPROVAL_SECRET in .env. It is never logged or returned.
"""
import hashlib
import hmac
import json
import os
import time

STUB_TOKEN = "STUB-TOKEN"   # kept only so firewall/__init__.py (the stub) still imports; it is NOT accepted any more

MIN_SECRET_LENGTH = 16


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
    """True only if the token is genuine, unexpired and matches every field. Never raises: any problem -> False."""
    try:
        if not isinstance(approval_token, str):
            return False
        expiry_text, _, given_mac = approval_token.partition(".")
        expiry = int(expiry_text)
        if time.time() > expiry:
            return False
        expected_mac = _sign(request_id, action, token_addr, to, amount, expiry)
        return hmac.compare_digest(given_mac.encode("utf-8"), expected_mac.encode("utf-8"))
    except Exception:
        return False