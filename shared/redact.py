"""Hide secrets in error text before it is shown to a person (UI, chat, API response, log line).

Provider errors from web3 / requests / openai often contain the full request URL, and an RPC URL such as
https://eth-sepolia.g.alchemy.com/v2/<API KEY> carries the API key. Anything that shows an exception to a
user must go through redact().

  * every URL is replaced by "[url hidden]"
  * the value of every secret-looking setting in the environment (RPC_URL_*, *_PRIVATE_KEY, *_API_KEY,
    *_SECRET) is replaced by "[hidden]", wherever it appears, even outside a URL
  * the result is one short line (no line breaks, at most `limit` characters)

Transaction hashes and addresses are NOT touched: they are public and the demo needs them.
"""
import os
import re

_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s'\"<>)\]]+")
_SECRET_NAME = re.compile(r"^(RPC_URL.*|.*_PRIVATE_KEY|.*_API_KEY|.*_SECRET)$")
MIN_SECRET_LENGTH = 8          # shorter values would hide ordinary words


def _secret_values() -> list:
    """Every secret setting's value, plus the parts of it that are secrets on their own: the key inside an
    RPC URL (its last path segment, e.g. .../v2/<API KEY>) and a private key written without its 0x."""
    found = set()
    for name, value in os.environ.items():
        value = value.strip()
        if not _SECRET_NAME.match(name) or len(value) < MIN_SECRET_LENGTH:
            continue
        found.add(value)
        if value.lower().startswith("0x"):
            found.add(value[2:])
        if "://" in value:
            found.add(value.split("?")[0].rstrip("/").rsplit("/", 1)[-1])
    return sorted((v for v in found if len(v) >= MIN_SECRET_LENGTH), key=len, reverse=True)   # longest first


def redact(value, limit: int = 300) -> str:
    """The text of `value` (an exception or a string) with URLs and known secrets hidden, on one line."""
    try:
        text = str(value)
    except Exception:
        text = type(value).__name__
    text = _URL.sub("[url hidden]", text)
    for secret in _secret_values():
        text = text.replace(secret, "[hidden]")
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "..."
