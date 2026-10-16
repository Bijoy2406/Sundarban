"""API tests use FastAPI TestClient and stubs; no chain/server needed."""
from fastapi.testclient import TestClient

import api.main as api
from shared.types import Decision, SimResult, TxPlan

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
    r = client.post("/api/execute", json={"action": "transfer", "to": "0xAlice", "amount": "10"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "executed"
    assert body["decision"]["decision"] == "allow"
    assert body["tx_hash"] == "0xabc123"
    assert [c[0] for c in calls] == ["plan", "simulate", "evaluate", "execute"]


def test_execute_deny_sends_nothing(monkeypatch):
    calls = _stub_pipeline(monkeypatch, "deny")
    r = client.post("/api/execute", json={"action": "transfer", "to": "0xAlice", "amount": "10"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "denied"
    assert body["tx_hash"] is None
    assert body["reasons"] == ["test deny"]
    assert "execute" not in [c[0] for c in calls]


def test_execute_ignores_tampered_client_decision(monkeypatch):
    calls = _stub_pipeline(monkeypatch, "deny")
    r = client.post("/api/execute", json={
        "action": "transfer", "to": "0xAlice", "amount": "10",
        "decision": {"decision": "allow", "approval_token": "forged"},
    })
    assert r.status_code == 200
    assert r.json()["status"] == "denied"
    assert "execute" not in [c[0] for c in calls]


def test_execute_ask_requires_separate_confirm(monkeypatch):
    calls = _stub_pipeline(monkeypatch, "ask")
    r = client.post("/api/execute", json={"action": "transfer", "to": "0xAlice", "amount": "10"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "awaiting_confirmation"
    assert body["tx_hash"] is None
    assert "execute" not in [c[0] for c in calls]
    confirmed = client.post("/api/confirm", json={"request_id": body["request_id"]})
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "executed"
    assert confirmed.json()["tx_hash"] == "0xabc123"
    assert [c[0] for c in calls] == ["plan", "simulate", "evaluate", "plan", "confirm", "execute"]


def test_confirm_rejects_unknown_or_replayed_request(monkeypatch):
    _stub_pipeline(monkeypatch, "ask")
    r = client.post("/api/confirm", json={"request_id": "not-pending"})
    assert r.status_code == 404


def test_sepolia_returns_explorer_link(monkeypatch):
    _stub_pipeline(monkeypatch, "allow")
    monkeypatch.setattr(api.chain, "network", lambda: "sepolia")
    r = client.post("/api/execute", json={"action": "transfer", "to": "0xAlice", "amount": "10"})
    assert r.json()["explorer_url"] == "https://sepolia.etherscan.io/tx/0xabc123"
