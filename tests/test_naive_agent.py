"""Tests for the deliberately unsafe local-only naive agent."""
from types import SimpleNamespace
from unittest.mock import Mock

import agent.naive_agent as naive_agent
from shared.types import SimResult, TxPlan


def _connected_chain(chain_id=31337):
    return SimpleNamespace(is_connected=lambda: True, eth=SimpleNamespace(chain_id=chain_id))


def _intent():
    return {
        "action": "transfer",
        "token": "0x" + "1" * 40,
        "to": "0x" + "2" * 40,
        "amount": "10",
        "unlimited": False,
        "rationale": "User requested action",
    }


def _plan():
    return TxPlan(
        chain_id=31337,
        from_addr="0x" + "3" * 40,
        to="0x" + "1" * 40,
        value=0,
        data="0x" + "a9059cbb" + "0" * 24 + "2" * 40 + "0" * 63 + "a",
        gas=100000,
        function="transfer(address,uint256)",
        args={},
        summary="Send 10 TUSD to 0x2222...2222",
    )


def test_refuses_non_local_chain_before_parsing(monkeypatch):
    monkeypatch.setattr(naive_agent.chain, "get_web3", lambda: _connected_chain(11155111))
    parse = Mock(side_effect=AssertionError("LLM must not be called on a non-local chain"))
    monkeypatch.setattr(naive_agent, "parse_intent", parse)

    reply = naive_agent.handle_message("Send tokens")

    assert reply.blocked is True
    assert "31337" in reply.text
    parse.assert_not_called()


def test_refuses_disconnected_node(monkeypatch):
    monkeypatch.setattr(
        naive_agent.chain,
        "get_web3",
        lambda: SimpleNamespace(is_connected=lambda: False, eth=SimpleNamespace(chain_id=31337)),
    )
    reply = naive_agent.handle_message("Send tokens")
    assert reply.blocked is True
    assert "connect" in reply.text.lower()


def test_executes_parsed_intent_without_firewall_policy(monkeypatch):
    tx_plan = _plan()
    monkeypatch.setattr(naive_agent.chain, "get_web3", lambda: _connected_chain())
    monkeypatch.setattr(naive_agent, "parse_intent", lambda text: _intent())
    monkeypatch.setattr(naive_agent, "plan", lambda req: tx_plan)
    monkeypatch.setattr(naive_agent, "simulate", lambda plan: SimResult(True, None, "10", None))
    monkeypatch.setattr(
        naive_agent,
        "token_binding",
        lambda plan: {
            "action": "transfer",
            "token": tx_plan.to.lower(),
            "to": _intent()["to"].lower(),
            "amount": "10",
        },
    )
    issued = {}
    def fake_issue_token(request_id, action, token, to, amount):
        issued.update(request_id=request_id, action=action, token=token, to=to, amount=amount)
        return "demo-token"
    monkeypatch.setattr(naive_agent, "issue_token", fake_issue_token)
    execute = Mock(return_value="0xdeadbeef")
    monkeypatch.setattr(naive_agent, "execute", execute)

    reply = naive_agent.handle_message("Send 10 TUSD", origin="public_feed")

    assert reply.blocked is False
    assert reply.tx_hash == "0xdeadbeef"
    assert reply.decision.decision == "allow"
    assert issued["action"] == "transfer"
    assert reply.decision.request_id == issued["request_id"]
    assert execute.call_args.args[0] is tx_plan
    assert execute.call_args.args[1].approval_token == "demo-token"
    assert "origin" not in _intent()
