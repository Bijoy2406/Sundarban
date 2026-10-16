"""Orchestration tests with a fake parser, engine and firewall; no chain/API needed."""
import pytest

import agent.agent as orchestrator
from shared.types import Decision, SimResult, TxPlan


@pytest.fixture
def setup(monkeypatch):
    orchestrator._PENDING.clear()
    calls = []
    plan = TxPlan(
        chain_id=31337, from_addr="0x" + "11" * 20, to="0x" + "22" * 20,
        value=0, data="0x", gas=60000, function="transfer(address,uint256)",
        args={}, summary="Send 10 TUSD to Alice",
    )
    sim = SimResult(ok=True, revert_reason=None, outflow="10", allowance_after=None)
    monkeypatch.setattr(orchestrator, "_resolve_token", lambda token: "0x" + "22" * 20)
    monkeypatch.setattr(orchestrator, "parse_intent", lambda text, **kwargs: {
        "action": "transfer", "token": "TUSD", "to": "0xAlice",
        "amount": "10", "unlimited": False, "rationale": "test",
    })
    monkeypatch.setattr(orchestrator.wallet_engine, "plan", lambda req: calls.append(("plan", req)) or plan)
    monkeypatch.setattr(orchestrator.wallet_engine, "simulate", lambda p: calls.append(("simulate", p)) or sim)
    monkeypatch.setattr(orchestrator.wallet_engine, "execute", lambda p, d: calls.append(("execute", p, d)) or "0xabc123")
    monkeypatch.setattr(orchestrator.firewall, "evaluate", lambda req, p, s: calls.append(("evaluate", req, p, s)) or Decision(req.request_id, "allow", reasons=["Allowed by test"]))
    monkeypatch.setattr(orchestrator.firewall, "confirm", lambda req, p: calls.append(("confirm", req, p)) or Decision(req.request_id, "allow", reasons=["Confirmed by test"], approval_token="test-token"))
    return calls, plan, sim


def test_allowed_request_runs_full_pipeline_and_returns_hash(setup):
    calls, _, _ = setup
    reply = orchestrator.handle_message("Send 10 TUSD to Alice")
    assert reply.blocked is False
    assert reply.tx_hash == "0xabc123"
    assert reply.decision.decision == "allow"
    assert [call[0] for call in calls] == ["plan", "simulate", "evaluate", "execute"]
    assert calls[0][1].origin == "user_chat"


def test_ask_waits_for_confirmation_then_executes(setup, monkeypatch):
    calls, _, _ = setup
    monkeypatch.setattr(orchestrator.firewall, "evaluate", lambda req, p, s: Decision(req.request_id, "ask", rule_ids=["ALW-01"], reasons=["New recipient"]))
    reply = orchestrator.handle_message("Send 10 TUSD to Alice")
    assert reply.tx_hash is None
    assert reply.decision.decision == "ask"
    assert "Nothing has been sent" in reply.text
    assert [call[0] for call in calls] == ["plan", "simulate"]
    confirmed = orchestrator.confirm_pending(reply.decision.request_id)
    assert confirmed.tx_hash == "0xabc123"
    assert confirmed.decision.decision == "allow"
    assert [call[0] for call in calls] == ["plan", "simulate", "confirm", "execute"]


def test_denied_request_never_executes(setup, monkeypatch):
    calls, _, _ = setup
    monkeypatch.setattr(orchestrator.firewall, "evaluate", lambda req, p, s: Decision(req.request_id, "deny", rule_ids=["PRV-01"], reasons=["Untrusted origin"]))
    reply = orchestrator.handle_message("Send 10 TUSD to Alice", origin="public_feed")
    assert reply.blocked is True
    assert reply.decision.decision == "deny"
    assert not any(call[0] == "execute" for call in calls)
    assert calls[0][1].origin == "public_feed"


def test_confirmation_cannot_be_replayed(setup, monkeypatch):
    calls, _, _ = setup
    monkeypatch.setattr(orchestrator.firewall, "evaluate", lambda req, p, s: Decision(req.request_id, "ask", reasons=["Needs confirmation"]))
    reply = orchestrator.handle_message("Send 10 TUSD to Alice")
    first = orchestrator.confirm_pending(reply.decision.request_id)
    second = orchestrator.confirm_pending(reply.decision.request_id)
    assert first.tx_hash == "0xabc123"
    assert second.blocked is True
    assert second.decision.decision == "deny"
    assert [call[0] for call in calls].count("execute") == 1


def test_parse_failure_returns_polite_blocked_reply(setup, monkeypatch):
    from agent.intents import IntentParseError
    monkeypatch.setattr(orchestrator, "parse_intent", lambda *a, **k: (_ for _ in ()).throw(IntentParseError()))
    reply = orchestrator.handle_message("unclear")
    assert reply.blocked is True
    assert "Sorry" in reply.text
    assert not setup[0]


def test_public_facade_keeps_contract_and_exposes_confirmation():
    import agent
    import inspect
    assert list(inspect.signature(agent.handle_message).parameters) == ["text", "origin"]
    assert callable(agent.confirm_pending)
