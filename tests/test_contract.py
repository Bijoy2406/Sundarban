"""Contract smoke test: every module imports and every facade function has the agreed signature.

If this fails after someone's change, the shared contract was broken.
"""
import inspect
from dataclasses import fields

import agent
import firewall
import wallet_engine
from agent import naive_agent
from firewall import audit, state, tokens
from shared.types import ActionRequest, AgentReply, Decision, SimResult, TxPlan


def _params(fn):
    return list(inspect.signature(fn).parameters)


def test_dataclass_fields():
    assert [f.name for f in fields(ActionRequest)] == [
        "request_id", "action", "token", "to", "amount", "unlimited", "origin", "rationale"]
    assert [f.name for f in fields(TxPlan)] == [
        "chain_id", "from_addr", "to", "value", "data", "gas", "function", "args", "summary"]
    assert [f.name for f in fields(SimResult)] == ["ok", "revert_reason", "outflow", "allowance_after"]
    assert [f.name for f in fields(Decision)] == [
        "request_id", "decision", "rule_ids", "reasons", "approval_token"]
    assert [f.name for f in fields(AgentReply)] == ["text", "decision", "tx_hash", "blocked"]


def test_signatures():
    assert _params(wallet_engine.plan) == ["req"]
    assert _params(wallet_engine.simulate) == ["plan"]
    assert _params(wallet_engine.execute) == ["plan", "decision"]
    assert _params(wallet_engine.balances) == []
    assert _params(wallet_engine.approvals) == []
    assert _params(firewall.evaluate) == ["req", "plan", "sim"]
    assert _params(firewall.confirm) == ["req", "plan"]
    assert _params(audit.log) == ["event"]
    assert _params(state.set_kill_switch) == ["on"]
    assert _params(agent.handle_message) == ["text", "origin"]
    assert _params(naive_agent.handle_message) == ["text", "origin"]
    assert _params(tokens.verify_token) == [
        "approval_token", "request_id", "action", "token_addr", "to", "amount"]


def test_stub_pipeline_runs_end_to_end():
    """simulate -> evaluate -> execute fit together (plan() is real now and needs a chain,
    so here the TxPlan is built by hand)."""
    req = ActionRequest("r1", "transfer", "0xTOKEN", "0xALICE", "10", False, "user_chat")
    plan = TxPlan(chain_id=31337, from_addr="0xFROM", to="0xTOKEN", value=0, data="0x", gas=21000,
                  function="transfer(address,uint256)", args={"to": "0xALICE", "value": 10}, summary="test")
    sim = wallet_engine.simulate(plan)
    decision = firewall.evaluate(req, plan, sim)
    assert decision.decision in {"allow", "ask", "deny"}
    tx_hash = wallet_engine.execute(plan, decision)
    assert tx_hash.startswith("0x")
