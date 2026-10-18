"""Orchestration tests with a fake parser, engine and firewall; no chain/API needed."""
import pytest

import agent.agent as orchestrator
from shared.types import Decision, SimResult, TxPlan

ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"   # Anvil public test account #1


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
        "action": "transfer", "token": "TUSD", "to": ALICE,
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


def test_a_name_instead_of_an_address_gets_a_helpful_message(setup, monkeypatch):
    calls = setup[0]
    monkeypatch.setattr(orchestrator, "parse_intent", lambda text, **kwargs: {
        "action": "transfer", "token": "TUSD", "to": "Alice",
        "amount": "10", "unlimited": False, "rationale": "test",
    })
    reply = orchestrator.handle_message("Send 10 TUSD to Alice")
    assert reply.blocked is True
    assert "full 0x address" in reply.text and "recipient" in reply.text
    assert calls == []                      # nothing was planned, simulated, evaluated or sent


def test_a_refused_execution_shows_the_reason(setup, monkeypatch):
    from wallet_engine import ExecutionRefused

    def refuse(plan, decision):
        raise ExecutionRefused("The approval token is invalid, expired, or does not match this transaction")
    monkeypatch.setattr(orchestrator.wallet_engine, "execute", refuse)
    reply = orchestrator.handle_message("Send 10 TUSD to Alice")
    assert reply.blocked is True and reply.tx_hash is None
    assert "Nothing was sent" in reply.text and "approval token is invalid" in reply.text


# ------------------------------------------------------------------ the confirmation text shows the whole address

def _plan_for(function, to, raw):
    from web3 import Web3
    from shared.types import TxPlan
    from wallet_engine import erc20
    data = Web3().eth.contract(abi=erc20.ERC20_ABI).encode_abi(function, args=[Web3.to_checksum_address(to), raw])
    return TxPlan(chain_id=31337, from_addr="0x" + "11" * 20, to="0x5FbDB2315678afecb367f032d93F642f64180aa3", value=0,
                  data=data, gas=60_000, function=f"{function}(address,uint256)", args={}, summary="Send 5 TUSD to 0x0000...cafE")


def test_the_ask_text_shows_the_complete_recipient_address():
    from agent.agent import _reply_for_decision
    from shared.types import Decision
    recipient = "0x000000000000000000000000000000000000cafE"
    plan = _plan_for("transfer", recipient, 5 * 10**18)
    reply = _reply_for_decision(Decision("r1", "ask", ["ALW-01"], ["New recipient."]), plan)
    assert "Recipient (full address): " + recipient + "." in reply.text
    assert "Nothing has been sent" in reply.text


def test_the_ask_text_for_an_approval_says_spender():
    from agent.agent import _full_address_line
    spender = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    assert _full_address_line(_plan_for("approve", spender, 10**18)) == f"Spender (full address): {spender}. "


def test_the_address_line_never_breaks_the_reply():
    from agent.agent import _full_address_line
    assert _full_address_line(None) == ""
