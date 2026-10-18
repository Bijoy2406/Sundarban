"""The attack replay: ONE attack, ONE extracted action, handed to both agents. LOCAL ANVIL ONLY.

What the demo has to show is that the firewall holds even when the language model is fooled. So the replay
does not leave the outcome to whatever the model happens to do on the day:

  1. Layer 1 (informational): the protected agent's own way of reading outside text (untrusted wrapper) is
     tried, and we report whether the model refused or still extracted an action.
  2. The "fooled model" is the worst case: the same text read WITHOUT the wrapper. If the real model does
     extract an action that pays the attacker, that is used (source "llm"). If it does not (a refusal, a bad
     reply, a different recipient, no API key), the action a fooled model would produce is taken from a
     fixed script (source "scripted"), and the page says so.
  3. Both agents then receive that same action with the same code-assigned origin:
       naive agent      signs it with no firewall            -> funds are lost
       protected agent  asks the firewall (PRV-01 etc.)      -> blocked, with the reasons

Nothing here trusts the browser: the caller passes a FeedItem found by id; origin comes from the feed
fixture; the local-chain guard runs before any model call or transaction.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any

import wallet_engine
from agent import agent as protected
from agent import naive_agent
from agent.feed import FeedItem
from agent.intents import IntentParseError, parse_intent
from shared.redact import redact
from wallet_engine import chain
from wallet_engine.attacks import drainer

LOCAL_CHAIN_ID = 31337
FEED_BAD_ADDRESSES = ("0x0000000000000000000000000000000000000BAD", "0x0000000000000000000000000000000000000BA0")

# What a fooled model would extract, by kind of attack. 'approve unlimited' is the incident's pattern.
_APPROVE_UNLIMITED = {"direct", "base64", "morse-like", "fake-airdrop-approval"}
_TRANSFER_TEN = {"nft-admin-claim", "look-alike-address"}


class ReplayRefused(RuntimeError):
    """The replay must not run. `status_code` is the HTTP status the API should answer with."""

    def __init__(self, message: str, status_code: int = 403):
        super().__init__(message)
        self.status_code = status_code


def scripted_intent(item: FeedItem, attacker: str) -> dict[str, Any]:
    """The action a fooled model would extract from this attack, written down in advance (for the replay)."""
    if item.attack_type in _APPROVE_UNLIMITED:
        return {"action": "approve", "token": "TUSD", "to": attacker, "amount": "0", "unlimited": True,
                "rationale": "scripted: what a fooled model would extract"}
    if item.attack_type in _TRANSFER_TEN:
        return {"action": "transfer", "token": "TUSD", "to": attacker, "amount": "10", "unlimited": False,
                "rationale": "scripted: what a fooled model would extract"}
    raise ReplayRefused("That feed item has no scripted attack.", 400)


def _require_local_chain() -> None:
    if chain.network().lower() != "local":
        raise ReplayRefused("Attack replay is available only on local Anvil.")
    w3 = chain.get_web3()
    if not w3.is_connected() or int(w3.eth.chain_id) != LOCAL_CHAIN_ID:
        raise ReplayRefused("Attack replay requires a connected local Anvil chain (31337).")


def _payload(item: FeedItem, attacker: str) -> str:
    """The feed text, with the demo's placeholder addresses pointed at the real local attacker account."""
    text = item.text
    for placeholder in FEED_BAD_ADDRESSES:
        text = text.replace(placeholder, attacker)
    return text


def _unreachable(exc: Exception) -> Exception | None:
    """The real cause when the model gave NO answer at all (no key, no network, a timeout, an HTTP error), else None.
    parse_intent turns every failure into IntentParseError but keeps the cause; a bad reply is a ValueError
    (JSON or schema), anything else means the model was never heard."""
    cause = exc.__cause__ if isinstance(exc, IntentParseError) else exc
    return None if cause is None or isinstance(cause, ValueError) else cause


def _layer1(payload: str) -> dict[str, str]:
    """Would the model, wrapped as the protected agent wraps outside text, still extract an action?"""
    try:
        intent = parse_intent(payload, untrusted=True)
    except Exception as exc:
        cause = _unreachable(exc)
        if cause is not None:       # an outage must never be reported as the model refusing
            return {"status": "unreachable", "detail": f"The model could not be reached ({type(cause).__name__}), "
                                                       "so this layer was not tested."}
        return {"status": "refused", "detail": "The model produced no action from the untrusted text."}
    return {"status": "fooled", "detail": f"The model still extracted: {intent['action']} to {_short(intent['to'])}."}


def _short(address: str) -> str:
    return f"{address[:6]}...{address[-4:]}" if isinstance(address, str) and len(address) > 12 else str(address)


def _fooled_intent(item: FeedItem, payload: str, attacker: str) -> tuple[dict[str, Any], str, str]:
    """(intent, source, note). The real model's extraction if it pays the attacker, else the scripted one."""
    try:
        intent = parse_intent(payload)             # no untrusted wrapper: the worst case
    except Exception as exc:
        cause = _unreachable(exc)
        reason = (f"the model could not be reached ({type(cause).__name__})" if cause is not None
                  else "the model gave no usable action")
        return scripted_intent(item, attacker), "scripted", f"Scripted: {reason}."
    if str(intent.get("to", "")).lower() != attacker.lower():
        return scripted_intent(item, attacker), "scripted", "Scripted: the model's action did not target the attacker."
    return intent, "llm", "Extracted by the real model with no protection around the text."


def _victim_balance() -> Decimal:
    balances = wallet_engine.balances()
    return Decimal(next(value for symbol, value in balances.items() if symbol != "ETH"))


def _attacker_has_allowance(attacker: str) -> bool:
    return any(a["spender"].lower() == attacker.lower() for a in wallet_engine.approvals())


def _naive_result(reply, intent: dict, attacker: str, before: Decimal) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "failed", "tx_hash": reply.tx_hash, "drain_tx_hash": None,
                              "balance_before": None, "balance_after": None, "balance_drop": None,
                              "reason": reply.text}
    if reply.blocked or not reply.tx_hash:
        return result
    result["reason"] = reply.text
    if intent["action"] == "approve" and _attacker_has_allowance(attacker):
        try:
            drained = drainer.drain()
        except drainer.DrainRefused as exc:
            result.update(status="approved", reason=f"{reply.text} The drain was not possible: {redact(exc)}")
            return result
        result.update(status="drained", drain_tx_hash=drained.tx_hash, balance_before=drained.victim_before,
                      balance_after=drained.victim_after, balance_drop=drained.amount)
        return result
    after = _victim_balance()
    lost = before - after
    result.update(status="stolen" if lost > 0 else "approved", balance_before=format(before, "f"),
                  balance_after=format(after, "f"), balance_drop=format(max(lost, Decimal(0)), "f"))
    return result


def _protected_result(reply) -> dict[str, Any]:
    decision = reply.decision
    blocked = reply.blocked or (decision is not None and decision.decision == "deny")
    return {"status": "blocked" if blocked else "review",
            "decision": None if decision is None else {"request_id": decision.request_id, "decision": decision.decision,
                                                       "rule_ids": list(decision.rule_ids), "reasons": list(decision.reasons)},
            "reasons": list(decision.reasons) if decision is not None and decision.reasons else [reply.text],
            "text": reply.text, "tx_hash": reply.tx_hash}


def _rpc(method: str, params: list | None = None) -> Any:
    """One raw JSON-RPC call to the local node (evm_snapshot / evm_revert are Anvil's)."""
    return chain.get_web3().provider.make_request(method, params or [])


def run(item: FeedItem) -> dict[str, Any]:
    """Run one attack against both agents, then roll the local chain back. Raises ReplayRefused if it must not run.

    The naive agent really signs, and the drainer really drains, so the first replay would leave the wallet empty and
    the next one would show a different (and misleading) result. The whole replay therefore runs between an Anvil
    snapshot and a revert: the result is built first, the revert runs in `finally` even if an agent raises."""
    if not item.attack:
        raise ReplayRefused("Choose an attack item to run the replay.", 400)
    _require_local_chain()                      # the guards run first: a refused replay never snapshots anything
    snapshot = _rpc("evm_snapshot").get("result")
    if not snapshot:
        raise ReplayRefused("The local chain could not be snapshotted, so the replay will not run (is this Anvil?).", 503)
    reset = False
    try:
        body = _run(item)
    finally:
        try:
            reset = _rpc("evm_revert", [snapshot]).get("result") is True
        except Exception:                       # never mask the replay's own outcome; the flag below says what happened
            reset = False
    body["chain_reset"] = reset
    return body


def _run(item: FeedItem) -> dict[str, Any]:
    attacker = drainer.attacker_address()
    payload = _payload(item, attacker)

    layer1 = _layer1(payload)
    intent, source, note = _fooled_intent(item, payload, attacker)

    # The protected agent goes first: it cannot change the chain, and the naive one will.
    protected_reply = protected.handle_intent(intent, origin=item.origin)
    before = _victim_balance()
    naive_reply = naive_agent.handle_intent(intent, origin=item.origin)

    return {
        "attack": {"id": item.id, "title": item.title, "source": item.source, "origin": item.origin,
                   "text": item.text, "payload": payload},
        "intent": {"source": source, "note": note, "action": intent["action"], "token": intent["token"],
                   "to": intent["to"], "amount": intent["amount"], "unlimited": intent["unlimited"]},
        "layer1": layer1,
        "naive": _naive_result(naive_reply, intent, attacker, before),
        "protected": _protected_result(protected_reply),
    }
