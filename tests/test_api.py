"""API tests use FastAPI TestClient and stubs; no chain/server needed."""
from fastapi.testclient import TestClient

import api.main as api
from tests.operator_key import operator_headers
from shared.types import Decision, SimResult, TxPlan

ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"      # a real address: the API now checks addresses like the agent does
client = TestClient(api.app)


def test_health_always_answers():
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["backend"] == "ok"
    assert {"network", "connected"} <= set(body["chain"])
    assert {"base_url", "model", "api_key_set"} == set(body["llm"])


def test_llm_status_never_returns_the_key():
    r = client.get("/api/llm/status")
    assert r.status_code == 200
    assert "api_key" not in r.json()


def test_plan_rejects_unknown_action():
    r = client.post("/api/plan", json={"action": "steal", "to": "0x0", "amount": "1"})
    assert r.status_code == 422


def _stub_pipeline(monkeypatch, decision_name="allow"):
    api._PENDING_CONFIRMATIONS.clear()
    calls = []
    tx_plan = TxPlan(chain_id=31337, from_addr="0x" + "11" * 20, to="0x" + "22" * 20,
                     value=0, data="0x", gas=60000, function="transfer(address,uint256)",
                     args={}, summary="Send 10 TUSD to Alice")
    sim = SimResult(ok=True, revert_reason=None, outflow="10", allowance_after=None)
    monkeypatch.setattr(api.chain, "token_address", lambda: "0x" + "33" * 20)
    monkeypatch.setattr(api.chain, "network", lambda: "local")
    monkeypatch.setattr(api.wallet_engine, "plan", lambda req: calls.append(("plan", req)) or tx_plan)
    monkeypatch.setattr(api.wallet_engine, "simulate", lambda p: calls.append(("simulate", p)) or sim)
    monkeypatch.setattr(api.firewall, "evaluate", lambda req, p, s: calls.append(("evaluate", req, p, s)) or Decision(
        req.request_id, decision_name, rule_ids=["TEST"], reasons=[f"test {decision_name}"],
        approval_token="test-token" if decision_name == "allow" else None))
    monkeypatch.setattr(api.firewall, "confirm", lambda req, p: calls.append(("confirm", req, p)) or Decision(
        req.request_id, "allow", rule_ids=["CONFIRMED"], reasons=["human confirmed"], approval_token="test-token"))
    monkeypatch.setattr(api.wallet_engine, "execute", lambda p, d: calls.append(("execute", p, d)) or "0xabc123")
    return calls


def test_execute_allow_sends_and_returns_hash(monkeypatch):
    calls = _stub_pipeline(monkeypatch, "allow")
    r = client.post("/api/execute", json={"action": "transfer", "to": ALICE, "amount": "10"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "executed"
    assert body["decision"]["decision"] == "allow"
    assert body["tx_hash"] == "0xabc123"
    assert [c[0] for c in calls] == ["plan", "simulate", "evaluate", "execute"]


def test_execute_deny_sends_nothing(monkeypatch):
    calls = _stub_pipeline(monkeypatch, "deny")
    r = client.post("/api/execute", json={"action": "transfer", "to": ALICE, "amount": "10"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "denied"
    assert body["tx_hash"] is None
    assert body["reasons"] == ["test deny"]
    assert "execute" not in [c[0] for c in calls]


def test_execute_ignores_tampered_client_decision(monkeypatch):
    calls = _stub_pipeline(monkeypatch, "deny")
    r = client.post("/api/execute", json={
        "action": "transfer", "to": ALICE, "amount": "10",
        "decision": {"decision": "allow", "approval_token": "forged"},
    })
    assert r.status_code == 200
    assert r.json()["status"] == "denied"
    assert "execute" not in [c[0] for c in calls]


def test_execute_ask_requires_separate_confirm(monkeypatch):
    calls = _stub_pipeline(monkeypatch, "ask")
    r = client.post("/api/execute", json={"action": "transfer", "to": ALICE, "amount": "10"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "awaiting_confirmation"
    assert body["tx_hash"] is None
    assert "execute" not in [c[0] for c in calls]
    confirmed = client.post("/api/confirm", json={"request_id": body["request_id"]}, headers=operator_headers())
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "executed"
    assert confirmed.json()["tx_hash"] == "0xabc123"
    assert [c[0] for c in calls] == ["plan", "simulate", "evaluate", "plan", "confirm", "execute"]


def test_confirm_rejects_unknown_or_replayed_request(monkeypatch):
    _stub_pipeline(monkeypatch, "ask")
    r = client.post("/api/confirm", json={"request_id": "not-pending"}, headers=operator_headers())
    assert r.status_code == 404


def test_sepolia_returns_explorer_link(monkeypatch):
    _stub_pipeline(monkeypatch, "allow")
    monkeypatch.setattr(api.chain, "network", lambda: "sepolia")
    r = client.post("/api/execute", json={"action": "transfer", "to": ALICE, "amount": "10"})
    assert r.json()["explorer_url"] == "https://sepolia.etherscan.io/tx/0xabc123"



def test_chat_endpoint_uses_agent_and_sets_user_origin(monkeypatch):
    from shared.types import AgentReply
    seen = {}
    def fake_handle(message, origin):
        seen.update(message=message, origin=origin)
        return AgentReply(text="I understood the request.", blocked=False)
    monkeypatch.setattr(api, "handle_agent_message", fake_handle)
    r = client.post("/api/chat", json={"message": "Explain my wallet"})
    assert r.status_code == 200
    assert r.json()["text"] == "I understood the request."
    assert r.json()["status"] == "completed"
    assert seen == {"message": "Explain my wallet", "origin": "user_chat"}


def test_chat_ask_can_only_be_confirmed_with_server_pending_request(monkeypatch):
    from shared.types import AgentReply
    decision = Decision("pending-123", "ask", rule_ids=["ALW-01"], reasons=["New recipient"])
    monkeypatch.setattr(api, "handle_agent_message", lambda message, origin: AgentReply(
        text="Please confirm.", decision=decision, blocked=False))
    monkeypatch.setattr(api, "has_pending_confirmation", lambda request_id: request_id == "pending-123")
    monkeypatch.setattr(api, "confirm_agent_pending", lambda request_id: AgentReply(
        text="Confirmed.", decision=Decision(request_id, "allow", reasons=["Confirmed"]), tx_hash="0xabc"))
    r = client.post("/api/chat", json={"message": "Send tokens"})
    assert r.status_code == 200
    assert r.json()["status"] == "awaiting_confirmation"
    assert r.json()["request_id"] == "pending-123"
    confirmed = client.post("/api/confirm", json={"request_id": "pending-123"}, headers=operator_headers())
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "executed"
    assert confirmed.json()["tx_hash"] == "0xabc"


def test_chat_rejects_empty_or_too_long_message():
    assert client.post("/api/chat", json={"message": ""}).status_code == 422
    assert client.post("/api/chat", json={"message": "x" * 4001}).status_code == 422


def test_kill_switch_endpoint_reports_and_updates_state(monkeypatch):
    current = {"on": True}
    monkeypatch.setattr(api.state, "kill_switch_on", lambda: current["on"])
    def set_state(value):
        current["on"] = value
    monkeypatch.setattr(api.state, "set_kill_switch", set_state)
    assert client.get("/api/security").json()["kill_switch_on"] is True
    r = client.post("/api/kill-switch", json={"enabled": False}, headers=operator_headers())
    assert r.status_code == 200
    assert r.json()["kill_switch_on"] is False
    assert client.post("/api/kill-switch", json={"enabled": True}).json()["kill_switch_on"] is True


def test_audit_endpoint_returns_entries_and_integrity(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(api.audit, "check", lambda: SimpleNamespace(ok=True, entries=2, head="hash", reason=None, line=None))
    monkeypatch.setattr(api.audit, "tail", lambda limit: [{"seq": 1, "event": {"event": "test"}, "hash": "hash"}])
    r = client.get("/api/audit?limit=10")
    assert r.status_code == 200
    assert r.json()["integrity"]["ok"] is True
    assert r.json()["entries"][0]["event"]["event"] == "test"
    assert client.get("/api/audit?limit=201").status_code == 422


def test_chat_agent_failure_returns_friendly_error(monkeypatch):
    def fail(message, origin):
        raise RuntimeError("secret stack details must not be returned")
    monkeypatch.setattr(api, "handle_agent_message", fail)
    r = client.post("/api/chat", json={"message": "hello"})
    assert r.status_code == 503
    assert "secret stack details" not in r.text
