"""Provenance: WHERE did this request come from? (Person 2 owns), issue #14, rule PRV-01.  HARDENED version.

Every ActionRequest has an `origin`, set by CODE from the channel the text arrived on
(never by the LLM). Only origins listed under `trusted_origins` in rules.yaml are trusted;
today that is just "user_chat" (the person typing to the wallet).

Everything else is untrusted: a public X reply ("public_feed"), NFT text ("nft_metadata"),
output of a tool ("tool_output"), a misspelling, an empty value, anything unknown.
An untrusted origin can never move money, however convincing its text is.

How this file fails SAFE
  * The origin must be a REAL `str` (not a look-alike subclass that lies about being equal) and must look
    like a plain channel name (letters, digits, _ . : -, at most 64 characters). Anything else: not trusted.
  * The match is exact: "USER_CHAT", " user_chat", "user_chat\\n", look-alike letters from other alphabets,
    invisible characters - none of them match.
  * If rules.yaml cannot be read, nobody is trusted.
  * The reason text NEVER repeats attacker-controlled text: an odd origin is shown as "unknown", so a request
    cannot smuggle instructions, line breaks or megabytes of text into the messages people (or an LLM) read.
Limit: this checks the channel of the INSTRUCTION. The code that builds the request must set `origin` itself
from the channel, never copy it from model output (that is the agent's job, Person 3).
"""
import re
from typing import Optional

from . import state

RULE_ID = "PRV-01"

_SAFE_NAME = re.compile(r"[A-Za-z0-9_.:\-]{1,64}")      # fullmatch: a trailing newline does NOT slip through


def describe(origin) -> str:
    """A safe way to show an origin in messages and logs: the name if it is a plain name, else 'unknown'."""
    return origin if type(origin) is str and _SAFE_NAME.fullmatch(origin) else "unknown"


def is_trusted(origin, trusted_origins=None) -> bool:
    """True only if `origin` is exactly one of the trusted origins.
    `trusted_origins` may be passed in (the policy engine passes the list it already loaded, so one decision
    uses one consistent copy of the rules); otherwise rules.yaml is read."""
    if type(origin) is not str or not _SAFE_NAME.fullmatch(origin):
        return False
    if trusted_origins is None:
        try:
            trusted_origins = state.load_rules()["trusted_origins"]
        except Exception:                  # cannot read the rules -> trust nobody
            return False
    try:
        return any(type(name) is str and name == origin for name in trusted_origins)
    except Exception:
        return False


def check(req, trusted_origins=None) -> Optional[tuple]:
    """Return None if the request may continue, or (rule_id, plain-English reason) if it must be denied."""
    try:
        origin = req.origin
    except Exception:
        origin = None
    if is_trusted(origin, trusted_origins):
        return None
    return (RULE_ID, f"The request came from an untrusted source ({describe(origin)}). "
                     f"Only messages you type yourself in the wallet chat can move money.")