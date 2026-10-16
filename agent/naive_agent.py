"""Deliberately naive agent for the local-chain attack demo.

This agent intentionally skips firewall.evaluate()/confirm(). It trusts the parsed
LLM intent, constructs a plan, and supplies the execution API with a token minted
directly from the plan's calldata. This is unsafe by design and MUST remain local
to Anvil (chain id 31337); it is only a demonstration, never a production agent.
"""
from __future__ import annotations

import uuid

from shared.types import ActionRequest, AgentReply, Decision
from agent.intents import IntentParseError, parse_intent
from wallet_engine import chain, execute, plan, simulate
from wallet_engine.binding import token_binding
from firewall.tokens import issue_token

LOCAL_CHAIN_ID = 31337


def handle_message(text: str, origin: str = "user_chat") -> AgentReply:
    """Execute the action extracted by the LLM, without firewall policy checks.

    A hard chain-id gate runs before any LLM call or planning. origin is supplied
    by the calling code and never comes from the model.
    """
    try:
        w3 = chain.get_web3()
        if not w3.is_connected():
            return AgentReply(text="The naive demo agent cannot connect to the local chain.", blocked=True)
        chain_id = int(w3.eth.chain_id)
        if chain_id != LOCAL_CHAIN_ID:
            return AgentReply(
                text=f"The naive demo agent is disabled on chain {chain_id}; use local Anvil (31337).",
                blocked=True,
            )

        intent = parse_intent(text)
        request_id = str(uuid.uuid4())
        req = ActionRequest(
            request_id=request_id,
            action=intent["action"],
            token=intent["token"],
            to=intent["to"],
            amount=intent["amount"],
            unlimited=intent["unlimited"],
            origin=origin,
            rationale=intent["rationale"],
        )

        tx_plan = plan(req)
        sim = simulate(tx_plan)
        if not sim.ok:
            return AgentReply(
                text=f"The naive demo transaction could not be simulated: {sim.revert_reason or 'unknown error'}.",
                blocked=True,
            )

        # Deliberately bypass firewall policy: issue a token directly for the
        # exact calldata binding so execute() can demonstrate the consequences
        # of trusting the LLM. Never copy this pattern into the protected agent.
        binding = token_binding(tx_plan)
        token = issue_token(
            request_id,
            binding["action"],
            binding["token"],
            binding["to"],
            binding["amount"],
        )
        decision = Decision(
            request_id=request_id,
            decision="allow",
            reasons=["Naive demo: LLM intent executed without firewall policy evaluation."],
            approval_token=token,
        )
        tx_hash = execute(tx_plan, decision)
        return AgentReply(
            text=f"Naive agent executed the LLM-extracted request: {tx_plan.summary}",
            decision=decision,
            tx_hash=tx_hash,
            blocked=False,
        )
    except IntentParseError as exc:
        return AgentReply(text=str(exc), blocked=True)
    except Exception as exc:
        # Keep internal exception details out of the chat response.
        return AgentReply(
            text=f"The naive demo agent could not complete the request ({type(exc).__name__}).",
            blocked=True,
        )
