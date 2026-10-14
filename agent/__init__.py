"""Agent facade (Person 3 owns this folder).

STUB: returns a fake reply so the UI and tests can run before the real LLM agent exists.
SIGNATURES must not change.
"""
from shared.types import AgentReply


def handle_message(text: str, origin: str = "user_chat") -> AgentReply:
    """STUB."""
    return AgentReply(text=f"STUB agent received: {text!r} (origin={origin})", blocked=False)
