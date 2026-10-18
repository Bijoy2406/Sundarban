"""The Preview / Execute forms must refuse a mistyped address exactly like the chat agent does (EIP-55 checksum),
instead of silently turning it into a different valid address."""
import pytest
from fastapi.testclient import TestClient

import api.main as api
from tests.operator_key import operator_headers
import wallet_engine
from shared.types import Decision, SimResult, TxPlan

TOKEN = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
BAD_CHECKSUM = "0x70997970C51812dc3A010C7d01b50e0d17dc79c8"      # mixed case, last letters wrong
client = TestClient(api.app)
PLAN = TxPlan(31337, "0x" + "1" * 40, TOKEN, 0, "0x", 60000, "transfer(address,uint256)", {}, "Send 10 TUSD")


@pytest.fixture(autouse=True)
def stand_ins(monkeypatch):
    monkeypatch.setenv("TOKEN_ADDRESS", TOKEN)
    monkeypatch.setattr(wallet_engine, "plan", lambda req: PLAN)
    monkeypatch.setattr(wallet_engine, "simulate", lambda plan: SimResult(True, None, "10", None))
    monkeypatch.setattr(api.firewall, "preview", lambda req, plan, sim: Decision(req.request_id, "ask", ["ALW-01"], ["new"]))
    monkeypatch.setattr(api.firewall, "evaluate", lambda req, plan, sim: Decision(req.request_id, "ask", ["ALW-01"], ["new"]))


@pytest.mark.parametrize("path", ["/api/plan", "/api/execute"])
def test_a_bad_checksum_is_refused_with_400(path):
    response = client.post(path, json={"action": "transfer", "to": BAD_CHECKSUM, "amount": "10"})
    assert response.status_code == 400
    assert "mistyped" in response.json()["detail"]


@pytest.mark.parametrize("path", ["/api/plan", "/api/execute"])
@pytest.mark.parametrize("action", ["approve", "revoke"])
def test_a_bad_checksum_spender_is_refused_too(path, action):
    response = client.post(path, json={"action": action, "to": BAD_CHECKSUM, "amount": "10"})
    assert response.status_code == 400 and "spender" in response.json()["detail"]


@pytest.mark.parametrize("path", ["/api/plan", "/api/execute"])
def test_a_name_instead_of_an_address_gets_the_friendly_message(path):
    response = client.post(path, json={"action": "transfer", "to": "Alice", "amount": "10"})
    assert response.status_code == 400
    assert "full 0x address" in response.json()["detail"]


def test_a_refused_execute_leaves_nothing_to_confirm():
    client.post("/api/execute", json={"action": "transfer", "to": BAD_CHECKSUM, "amount": "10"})
    assert client.post("/api/confirm", json={"request_id": "anything"}, headers=operator_headers()).status_code == 404


@pytest.mark.parametrize("address", [ALICE, ALICE.lower(), "0x" + ALICE[2:].upper()])
@pytest.mark.parametrize("path", ["/api/plan", "/api/execute"])
def test_valid_spellings_still_work(path, address):
    response = client.post(path, json={"action": "transfer", "to": address, "amount": "10"})
    assert response.status_code == 200, response.text
