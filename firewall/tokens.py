"""Approval tokens (Person 2 owns). STUB for now.

Real version: HMAC-SHA256 over request_id, action, token, to, amount and an expiry,
secret from APPROVAL_SECRET, compared with hmac.compare_digest.
"""

STUB_TOKEN = "STUB-TOKEN"


def issue_token(request_id: str, action: str, token: str, to: str, amount: str, ttl_seconds: int = 120) -> str:
    """STUB: returns a fixed string."""
    return STUB_TOKEN


def verify_token(approval_token: str, request_id: str, action: str, token_addr: str, to: str, amount: str) -> bool:
    """STUB: accepts only the fixed stub string. The wallet engine calls this before sending."""
    return approval_token == STUB_TOKEN
