"""Provider errors contain the RPC URL, and the RPC URL contains the API key. None of it may reach a user."""
import importlib

import pytest
import requests
from fastapi.testclient import TestClient

import api.main as api
import wallet_engine
from shared.redact import redact
from shared.types import TxPlan
from wallet_engine import chain

simulate = importlib.import_module("wallet_engine.simulate")
KEY = "PrivateAlchemyKey0123456789"
URL = f"https://eth-sepolia.g.alchemy.com/v2/{KEY}"
client = TestClient(api.app)


def provider_error(*args, **kwargs):
    raise requests.HTTPError(f"429 Client Error: Too Many Requests for url: {URL}")


@pytest.fixture(autouse=True)
def secret_env(monkeypatch):
    monkeypatch.setenv("RPC_URL_SEPOLIA", URL)
    monkeypatch.setenv("SEPOLIA_PRIVATE_KEY", "0x" + "ab" * 32)
    monkeypatch.setenv("LLM_API_KEY", "sk-test-llm-key-0123456789")


# ------------------------------------------------------------------ the helper

def test_a_url_is_hidden():
    text = redact(f"400 Client Error: Bad Request for url: {URL}")
    assert KEY not in text and "alchemy" not in text and "[url hidden]" in text


def test_every_kind_of_url_is_hidden():
    for url in ("http://127.0.0.1:8545", "wss://node.example.org/ws?token=abc", "https://x.io/a/b?c=d#e"):
        assert "://" not in redact(f"failed ({url}) twice")


def test_the_value_of_a_secret_setting_is_hidden_even_outside_a_url():
    text = redact(f"bad key {KEY} and sk-test-llm-key-0123456789 and {'ab' * 32}")
    assert KEY not in text and "sk-test-llm-key" not in text and "ab" * 32 not in text
    assert text.count("[hidden]") == 3


def test_short_or_empty_settings_do_not_hide_ordinary_words(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "abc")
    monkeypatch.setenv("APPROVAL_SECRET", "")
    assert redact("abc is fine") == "abc is fine"


def test_public_hashes_and_addresses_are_kept():
    tx = "0x" + "cd" * 32
    address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    assert redact(f"tx {tx} to {address}") == f"tx {tx} to {address}"


def test_output_is_one_short_line():
    text = redact("line one\nline two\r\n\tline three " + "x" * 1000, limit=50)
    assert "\n" not in text and "\t" not in text and len(text) <= 53


def test_redact_never_raises():
    class Weird:
        def __str__(self):
            raise RuntimeError("no text")
    assert redact(Weird()) == "Weird"
    assert redact(None) == "None"


# ------------------------------------------------------------------ the places that show errors

def test_health_does_not_show_the_key(monkeypatch):
    monkeypatch.setattr(chain, "get_web3", provider_error)
    body = client.get("/api/health").json()
    assert KEY not in str(body) and "alchemy" not in str(body)


def test_wallet_does_not_show_the_key(monkeypatch):
    monkeypatch.setattr(wallet_engine, "balances", provider_error)
    monkeypatch.setattr(api.chain, "wallet_address", lambda: "0x" + "11" * 20)
    monkeypatch.setattr(api.chain, "token_address", lambda: "0x" + "22" * 20)
    reply = client.get("/api/wallet")
    assert reply.status_code == 503
    assert KEY not in reply.text and "alchemy" not in reply.text and "Cannot read wallet" in reply.text


def test_simulation_does_not_show_the_key(monkeypatch):
    monkeypatch.setattr(chain, "get_web3", provider_error)
    plan = TxPlan(chain_id=1, from_addr="0x" + "11" * 20, to="0x" + "22" * 20, value=0, data="0x", gas=60000,
                  function="", args={}, summary="")
    result = simulate.run(plan)
    assert result.ok is False
    assert KEY not in result.revert_reason and "alchemy" not in result.revert_reason


def test_a_contract_revert_reason_is_still_readable(monkeypatch):
    class Reverted(Exception):
        message = "execution reverted: TestUSD: insufficient balance"
    assert simulate._revert_reason(Reverted()) == "TestUSD: insufficient balance"


def test_llm_test_does_not_show_the_key(monkeypatch):
    from agent import llm

    def boom():
        raise requests.HTTPError(f"401 for url: https://api.example.com/v1 key=sk-test-llm-key-0123456789")
    monkeypatch.setattr(llm, "get_client", boom)
    result = llm.test_connection()
    assert result["ok"] is False and "sk-test-llm-key" not in result["error"] and "://" not in result["error"]
