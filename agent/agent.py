"""Protected wallet agent orchestration (issue #23).

The LLM extracts intent only. Trusted Python assigns provenance; the engine builds
and simulates the exact transaction; the deterministic firewall decides; execution
happens only after an "allow" or an explicit confirmation of an "ask".
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass

from web3 import Web3

import firewall
import wallet_engine
from agent.intents import IntentParseError, check_intent, parse_intent
from agent.resolve import UserInputError, require_address
from agent.resolve import resolve_token as _resolve_token
from shared.types import ActionRequest, AgentReply, Decision, TxPlan
from wallet_engine.binding import token_binding

_PENDING_TTL_SECONDS = 600
_MAX_PENDING = 1000
_PENDING_LOCK = threading.RLock()


@dataclass
class _PendingAction:
    request: ActionRequest
    plan: TxPlan
    created_at: float


_PENDING: dict[str, _PendingAction] = {}


def _prune_pending(now: float) -> None:
    expired = [
        request_id for request_id, item in _PENDING.items()
        if now - item.created_at > _PENDING_TTL_SECONDS
    ]
    for request_id in expired:
        _PENDING.pop(request_id, None)
    while len(_PENDING) > _MAX_PENDING:
        oldest = min(_PENDING, key=lambda key: _PENDING[key].created_at)
        _PENDING.pop(oldest, None)


def _full_address_line(tx_plan: TxPlan | None) -> str:
    """The complete 42-character address the person is about to confirm. Summaries show only 0x1234...abcd, and
    a look-alike address can copy those 8 characters; the full address is what must be compared."""
    try:
        role = "Spender" if token_binding(tx_plan)["action"] in ("approve", "revoke") else "Recipient"
        return f"{role} (full address): {Web3.to_checksum_address(token_binding(tx_plan)['to'])}. "
    except Exception:
        return ""


def _reasons(decision: Decision) -> str:
    return " ".join(str(reason) for reason in (decision.reasons or [])) or (
        f"The firewall decision is {decision.decision}."
    )


def _reply_for_decision(decision: Decision, tx_plan: TxPlan | None = None) -> AgentReply:
    reasons = _reasons(decision)
    if decision.decision == "deny":
        return AgentReply(
            text=f"I can't execute this request because the wallet firewall denied it. {reasons}",
            decision=decision,
            blocked=True,
        )
    if decision.decision == "ask":
        summary = tx_plan.summary if tx_plan else "the requested transaction"
        return AgentReply(
            text=f"Confirmation required for {summary}. {_full_address_line(tx_plan)}{reasons} Nothing has been sent. "
                 f"Confirm request {decision.request_id} through the trusted confirmation UI.",
            decision=decision,
            blocked=False,
        )
    if decision.decision != "allow":
        refused = Decision(
            request_id=decision.request_id,
            decision="deny",
            rule_ids=["DEF-01"],
            reasons=["The firewall returned an unknown decision; refusing to execute."],
        )
        return AgentReply(
            text="I can't execute this request because the firewall returned an unexpected decision.",
            decision=refused,
            blocked=True,
        )
    return AgentReply(text=f"Safety checks passed. {reasons}", decision=decision, blocked=False)


PENDING_PREFIX = "Sent but not yet confirmed"


def _pending_reply(exc, decision: Decision) -> AgentReply:
    """The transaction was broadcast but no receipt came in time: show the hash, never say 'failed'."""
    return AgentReply(text=str(exc), decision=decision, tx_hash=exc.tx_hash, blocked=False)


def is_pending(reply: AgentReply) -> bool:
    """True for a reply that carries a broadcast transaction whose outcome is not known yet."""
    return bool(reply.tx_hash) and reply.text.startswith(PENDING_PREFIX)


_UNTRUSTED_ORIGINS = {"public_feed", "nft_metadata", "tool_output"}


def handle_message(text: str, origin: str = "user_chat") -> AgentReply:
    """Parse, plan, simulate, evaluate and execute only if the firewall allows.

    For an "ask" decision, the request and exact plan are kept briefly in memory;
    no transaction is sent. Call confirm_pending(request_id) only after a human
    explicitly confirms through a trusted UI.
    """
    return _handle(lambda: parse_intent(text, untrusted=(origin in _UNTRUSTED_ORIGINS)), origin)


def handle_intent(intent: dict, origin: str = "user_chat") -> AgentReply:
    """The same pipeline as handle_message for an intent that was already extracted (the attack replay hands
    both agents the SAME extracted action). The intent is re-validated with the strict schema, and the
    firewall still decides from the code-assigned origin, never from anything the intent says."""
    return _handle(lambda: check_intent(intent), origin)


def _handle(get_intent, origin: str) -> AgentReply:
    try:
        intent = get_intent()
        req = ActionRequest(
            request_id=str(uuid.uuid4()),
            action=intent["action"],
            token=_resolve_token(intent["token"]),
            to=require_address(intent["to"], intent["action"]),
            amount=intent["amount"],
            unlimited=intent["unlimited"],
            origin=origin,
            rationale=intent["rationale"],
        )
        try:
            tx_plan = wallet_engine.plan(req)
        except ValueError as exc:
            raise UserInputError(f"I can't build that transaction: {exc}") from exc
        sim = wallet_engine.simulate(tx_plan)
        decision = firewall.evaluate(req, tx_plan, sim)

        if decision.decision == "ask":
            with _PENDING_LOCK:
                now = time.monotonic()
                _prune_pending(now)
                _PENDING[req.request_id] = _PendingAction(req, tx_plan, now)
                _prune_pending(now)
            return _reply_for_decision(decision, tx_plan)

        reply = _reply_for_decision(decision, tx_plan)
        if decision.decision != "allow":
            return reply

        tx_hash = wallet_engine.execute(tx_plan, decision)
        return AgentReply(
            text=f"Done. {tx_plan.summary} Transaction: {tx_hash}. { _reasons(decision) }",
            decision=decision,
            tx_hash=tx_hash,
            blocked=False,
        )
    except (IntentParseError, UserInputError) as exc:
        return AgentReply(text=str(exc), blocked=True)
    except wallet_engine.ExecutionPending as exc:
        return _pending_reply(exc, decision)
    except wallet_engine.ExecutionRefused as exc:
        # Written by the wallet engine in plain English and safe to show (it never contains a secret).
        return AgentReply(text=f"Nothing was sent. {exc}", blocked=True)
    except Exception as exc:
        # Never leak provider errors, transaction internals, or secrets into chat.
        return AgentReply(
            text=f"I couldn't safely complete that request ({type(exc).__name__}). No success is being reported.",
            blocked=True,
        )


def confirm_pending(request_id: str) -> AgentReply:
    """Continue a pending "ask" only after a trusted UI has obtained human consent."""
    with _PENDING_LOCK:
        now = time.monotonic()
        _prune_pending(now)
        pending = _PENDING.pop(request_id, None)
    if pending is None:
        decision = Decision(
            request_id=request_id,
            decision="deny",
            rule_ids=["CNF-01"],
            reasons=["This confirmation is missing, expired, or has already been used."],
        )
        return AgentReply(
            text="I can't confirm this transaction because the request is missing, expired, or already used.",
            decision=decision,
            blocked=True,
        )

    try:
        decision = firewall.confirm(pending.request, pending.plan)
        reply = _reply_for_decision(decision, pending.plan)
        if decision.decision != "allow":
            return reply
        tx_hash = wallet_engine.execute(pending.plan, decision)
        return AgentReply(
            text=f"Confirmed and executed. {pending.plan.summary} Transaction: {tx_hash}. {_reasons(decision)}",
            decision=decision,
            tx_hash=tx_hash,
            blocked=False,
        )
    except wallet_engine.ExecutionPending as exc:
        return _pending_reply(exc, decision)
    except wallet_engine.ExecutionRefused as exc:
        return AgentReply(text=f"Nothing was sent. {exc}", blocked=True)
    except Exception as exc:
        return AgentReply(
            text=f"I couldn't safely complete the confirmation ({type(exc).__name__}). No success is being reported.",
            blocked=True,
        )



def has_pending_confirmation(request_id: str) -> bool:
    """Return whether an unexpired agent confirmation exists, without consuming it."""
    with _PENDING_LOCK:
        _prune_pending(time.monotonic())
        return request_id in _PENDING
