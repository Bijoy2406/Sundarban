"""An RPC URL carries its API key. Whatever an exception puts in front of a person (HTTP error body, chat reply,
evidence CSV) must pass through shared/redact.py. These tests use a FAKE key and a deliberately broken URL, so the
error text of the HTTP library contains the whole URL, exactly as a misconfigured .env would."""
import csv
import importlib.util
from pathlib import Path

import pytest
from eth_account import Account
from fastapi.testclient import TestClient

import agent.agent as protected
import api.main as api
import wallet_engine
from shared.types import ActionRequest

ROOT = Path(__file__).resolve().parents[1]
FAKE_KEY = "FAKEKEY0123456789"
TOKEN = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
FORM = {"action": "transfer", "to": ALICE, "amount": "10"}
client = TestClient(api.app)


@pytest.fixture(autouse=True)
def broken_rpc(monkeypatch):
    """No scheme in the URL: `requests` raises MissingSchema (a ValueError) whose text is the full URL."""
    monkeypatch.setenv("ACTIVE_NETWORK", "local")
    monkeypatch.setenv("RPC_URL_LOCAL", f"rpc.example.invalid/v2/{FAKE_KEY}")
    monkeypatch.setenv("RPC_URL_SEPOLIA", f"https://sepolia.example.invalid/v2/{FAKE_KEY}")
    monkeypatch.setenv("TOKEN_ADDRESS", TOKEN)
    monkeypatch.setenv("WALLET_PRIVATE_KEY", Account.create().key.hex())


def test_the_fixture_really_produces_the_leak_text():
    """Guard for the tests below: without redaction the raw library error contains the fake key."""
    with pytest.raises(ValueError) as excinfo:
        wallet_engine.plan(ActionRequest("g1", "transfer", TOKEN, ALICE, "10", False, "user_chat"))
    assert FAKE_KEY in str(excinfo.value)


@pytest.mark.parametrize("path", ["/api/plan", "/api/execute"])
def test_http_errors_do_not_echo_the_rpc_url(path):
    response = client.post(path, json=FORM)
    assert response.status_code == 400
    assert FAKE_KEY not in response.text


def test_confirm_errors_do_not_echo_the_rpc_url():
    api._remember_ask(ActionRequest("leak-confirm", "transfer", TOKEN, ALICE, "10", False, "user_chat"))
    response = client.post("/api/confirm", json={"request_id": "leak-confirm"})
    assert response.status_code == 400
    assert FAKE_KEY not in response.text


def test_chat_replies_do_not_echo_the_rpc_url(monkeypatch):
    monkeypatch.setattr(protected, "parse_intent", lambda text, untrusted=False: {
        "action": "transfer", "token": TOKEN, "to": ALICE, "amount": "10", "unlimited": False, "rationale": "x"})
    response = client.post("/api/chat", json={"message": "send 10 TUSD to alice"})
    assert FAKE_KEY not in response.text
    assert "can't build that transaction" in response.json()["text"]       # still a useful message


def _evidence_module():
    spec = importlib.util.spec_from_file_location("evidence_run", ROOT / "wallet_engine" / "scripts" / "evidence_run.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_evidence_csv_does_not_store_the_rpc_key(monkeypatch, tmp_path):
    import requests
    evidence = _evidence_module()

    def refused(req):
        raise requests.exceptions.ConnectionError(
            "HTTPSConnectionPool(host='sepolia.example.invalid', port=443): Max retries exceeded with url: "
            f"/v2/{FAKE_KEY} (Caused by NewConnectionError)")
    monkeypatch.setattr(wallet_engine, "plan", refused)
    out = tmp_path / "tx.csv"
    rows = evidence.run([evidence.SCENARIOS[0]], {"A": ALICE, "B": ALICE}, None, TOKEN, "sepolia", out,
                        confirm=lambda *a: True)
    assert rows[0]["status"] == "error"
    assert FAKE_KEY not in out.read_text()
    assert FAKE_KEY not in rows[0]["note"]
    assert "ConnectionError" in list(csv.DictReader(out.open()))[0]["note"]   # the kind of failure is still recorded
