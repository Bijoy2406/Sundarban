"""Public agent facade.

handle_message keeps the shared contract stable. confirm_pending is called only
from a trusted confirmation endpoint after an explicit human action.
"""
from shared.types import AgentReply
from .agent import confirm_pending, handle_message, has_pending_confirmation

__all__ = ["AgentReply", "handle_message", "confirm_pending", "has_pending_confirmation"]
