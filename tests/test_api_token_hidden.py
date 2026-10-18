"""The approval token is a server-side secret: it is consumed by wallet_engine.execute() and must never be sent to the
browser. The firewall and the chain are replaced by stand-ins; the HTTP layer is the real one."""
import pytest
from fastapi.testclient import TestClient

import api.main as api
import wallet_engine
from shared.types import ActionRequest, AgentReply, Decision, SimResult, TxPlan

SECRET_TOKEN = "1893456000.deadbeefcafe0123456789SECRETTOKENTEXT"
TOKEN = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
TX = "0x" + "ab" * 32
FORM = {"action": "transfer", "to": ALICE, "amount": "10"}
client = TestClient(api.app)

PLAN = TxPlan(31337, "0x" + "1" * 40, TOKEN, 0, "0x", 60000, "transfer(address,uint256)", {}, "Send 10 TUSD")
SIM = SimResult(True, None, "10", None)


def _allow():
    return Decision("req-1", "allow", ["ALLOW"], ["ok"], SECRET_TOKEN)


def _assert_no_token(response):
    assert SECRET_TOKEN not in response.text
    decision = response.json().get("decision")
    if decision is not None:
        assert decision["approval_token"] is None


def test_execute_response_has_no_token(monkeypatch):
    monkeypatch.setattr(api, "_plan_simulate_evaluate", lambda req: (PLAN, SIM, _allow()))
    seen = {}
    monkeypatch.setattr(wallet_engine, "execute", lambda plan, decision: seen.setdefault("token", decision.approval_token) and TX)
    response = client.post("/api/execute", json=FORM)
    assert response.status_code == 200 and response.json()["status"] == "executed"
    assert seen["token"] == SECRET_TOKEN                       # the server still USES the token to send
    _assert_no_token(response)


def test_pending_execute_response_has_no_token(monkeypatch):
    monkeypatch.setattr(api, "_plan_simulate_evaluate", lambda req: (PLAN, SIM, _allow()))

    def slow(plan, decision):
        raise wallet_engine.ExecutionPending(TX)
    monkeypatch.setattr(wallet_engine, "execute", slow)
    response = client.post("/api/execute", json=FORM)
    assert response.json()["status"] == "pending"
    _assert_no_token(response)


def test_confirm_response_has_no_token(monkeypatch):
    api._remember_ask(ActionRequest("req-1", "transfer", TOKEN, ALICE, "10", False, "user_chat"))
    monkeypatch.setattr(wallet_engine, "plan", lambda req: PLAN)
    monkeypatch.setattr(api.firewall, "confirm", lambda req, plan: _allow())
    monkeypatch.setattr(wallet_engine, "execute", lambda plan, decision: TX)
    response = client.post("/api/confirm", json={"request_id": "req-1"})
    assert response.json()["status"] == "executed"
    _assert_no_token(response)


def test_chat_and_agent_confirm_responses_have_no_token(monkeypatch):
    reply = AgentReply(text="Done.", decision=_allow(), tx_hash=TX, blocked=False)
    monkeypatch.setattr(api, "handle_agent_message", lambda text, origin="user_chat": reply)
    chat = client.post("/api/chat", json={"message": "send 10 TUSD to alice"})
    assert chat.json()["status"] == "executed"
    _assert_no_token(chat)

    monkeypatch.setattr(api, "has_pending_confirmation", lambda request_id: True)
    monkeypatch.setattr(api, "confirm_agent_pending", lambda request_id: reply)
    confirm = client.post("/api/confirm", json={"request_id": "chat-ask-1"})
    assert confirm.json()["status"] == "executed"
    _assert_no_token(confirm)
