"""Naive agent: NO firewall. Exists only to show the danger in the demo (Person 3 owns).

Must refuse to run unless the chain is the local Anvil chain. STUB for now.
"""
from shared.types import AgentReply


def handle_message(text: str, origin: str = "user_chat") -> AgentReply:
    """STUB."""
    return AgentReply(text=f"STUB naive agent received: {text!r} (origin={origin})", blocked=False)
