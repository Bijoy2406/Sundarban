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

import firewall
import wallet_engine
from wallet_engine import chain, erc20
from agent.intents import IntentParseError, parse_intent
from shared.types import ActionRequest, AgentReply, Decision, TxPlan

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


def _resolve_token(token: str) -> str:
    """Resolve a configured token symbol to its contract; never guess other symbols."""
    if token.upper() == "ETH":
        return token
    if len(token) == 42 and token[:2].lower() == "0x":
        return token
    w3 = chain.get_web3()
    address = chain.token_address()
    configured_symbol = erc20.token_contract(w3, address).functions.symbol().call()
    if token.casefold() != str(configured_symbol).casefold():
        raise ValueError(f"Unsupported token symbol: {token}")
    return address


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
            text=f"Confirmation required for {summary}. {reasons} Nothing has been sent. "
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


def handle_message(text: str, origin: str = "user_chat") -> AgentReply:
    """Parse, plan, simulate, evaluate and execute only if the firewall allows.

    For an "ask" decision, the request and exact plan are kept briefly in memory;
    no transaction is sent. Call confirm_pending(request_id) only after a human
    explicitly confirms through a trusted UI.
    """
    try:
        intent = parse_intent(text, untrusted=(origin in {"public_feed", "nft_metadata", "tool_output"}))
        req = ActionRequest(
            request_id=str(uuid.uuid4()),
            action=intent["action"],
            token=_resolve_token(intent["token"]),
            to=intent["to"],
            amount=intent["amount"],
            unlimited=intent["unlimited"],
            origin=origin,
            rationale=intent["rationale"],
        )
        tx_plan = wallet_engine.plan(req)
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
    except IntentParseError as exc:
        return AgentReply(text=str(exc), blocked=True)
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
    except Exception as exc:
        return AgentReply(
            text=f"I couldn't safely complete the confirmation ({type(exc).__name__}). No success is being reported.",
            blocked=True,
        )
