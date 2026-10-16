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
    assert _params(firewall.preview) == ["req", "plan", "sim"]
    assert _params(audit.log) == ["event"]
    assert _params(state.set_kill_switch) == ["on"]
    assert _params(agent.handle_message) == ["text", "origin"]
    assert _params(naive_agent.handle_message) == ["text", "origin"]
    assert _params(tokens.verify_token) == [
        "approval_token", "request_id", "action", "token_addr", "to", "amount"]


def test_firewall_facade_returns_a_valid_decision():
    """evaluate() and confirm() must always return a Decision with a known value.
    (simulate/execute are real now; they are covered in tests/test_simulate_execute.py.)"""
    req = ActionRequest("r1", "transfer", "0xTOKEN", "0xALICE", "10", False, "user_chat")
    plan = TxPlan(chain_id=31337, from_addr="0xFROM", to="0xTOKEN", value=0, data="0x", gas=21000,
                  function="transfer(address,uint256)", args={"to": "0xALICE", "value": 10}, summary="test")
    sim = SimResult(ok=True, revert_reason=None, outflow="10", allowance_after=None)
    for decision in (firewall.evaluate(req, plan, sim), firewall.confirm(req, plan)):
        assert isinstance(decision, Decision)
        assert decision.decision in {"allow", "ask", "deny"}
        assert decision.request_id == "r1"
