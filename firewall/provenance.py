"""Provenance: WHERE did this request come from? (Person 2 owns), issue #14, rule PRV-01.

Every ActionRequest has an `origin`, set by CODE from the channel the text arrived on
(never by the LLM). Only origins listed under `trusted_origins` in rules.yaml are trusted;
today that is just "user_chat" (the person typing to the wallet).

Everything else is untrusted: a public X reply ("public_feed"), NFT text ("nft_metadata"),
output of a tool ("tool_output"), a misspelling, an empty value, anything unknown.
An untrusted origin can never move money, however convincing its text is.

Fail closed: if the origin is odd or rules.yaml cannot be read, the answer is "not trusted".
The policy engine (policy.py, #15) calls check(req) first and denies on any hit.
"""
from typing import Optional

from shared.types import ActionRequest

from . import state

RULE_ID = "PRV-01"


def is_trusted(origin) -> bool:
    """True only if `origin` is exactly one of the trusted origins in rules.yaml."""
    if not isinstance(origin, str):
        return False
    try:
        trusted = state.load_rules()["trusted_origins"]
    except Exception:          # cannot read the rules -> trust nobody
        return False
    return origin in trusted   # exact match: "USER_CHAT", " user_chat" and "user_chat2" are NOT trusted


def check(req: ActionRequest) -> Optional[tuple]:
    """Return None if the request may continue, or (rule_id, plain-English reason) if it must be denied."""
    origin = getattr(req, "origin", None)
    if is_trusted(origin):
        return None
    shown = origin if isinstance(origin, str) and origin.strip() else "unknown"
    return (RULE_ID, f"The request came from an untrusted source ({shown}). "
                     f"Only messages you type yourself in the wallet chat can move money.")