"""LIVE tests: both agents and the API against the REAL firewall and a REAL local chain.

The agents' mocked tests could not catch real-world mistakes (for example the LLM naming the token "TUSD" instead of
giving an address, or a Preview being counted as spending). These tests use no mocks except the LLM, which is
replaced by a fake that returns exactly what a real model returns for these messages.

They SKIP unless a local Anvil (chain 31337) with TestUSD deployed is running (`anvil`, then
`python wallet_engine/scripts/deploy.py`). Every test is rolled back with evm_snapshot / evm_revert.
"""
import os

import pytest
from fastapi.testclient import TestClient
from web3 import Web3

import api.main as api
import agent.agent as protected
import agent.naive_agent as naive
import wallet_engine
from firewall import audit, policy, state
from wallet_engine import chain, erc20
from wallet_engine.attacks import drainer

ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"      # allowlisted; also Anvil account #1 = the attacker
CAFE = Web3.to_checksum_address("0x" + "0" * 36 + "cafe")  # a first-time recipient that is NOT on the allowlist
ONE = 10**18
client = TestClient(api.app)


@pytest.fixture(scope="module")
def live():
    try:
        st = chain.status()
    except Exception:
        pytest.skip("chain not configured")
    if not st.get("connected") or st.get("chain_id") != 31337 or not st.get("token_deployed"):
        pytest.skip("local anvil with deployed TestUSD not available")
    if not os.getenv("ATTACKER_PRIVATE_KEY"):
        pytest.skip("ATTACKER_PRIVATE_KEY not set")
    return st


@pytest.fixture
def env(live, tmp_path, monkeypatch):
    """Real firewall with Alice allowlisted, the real chain, a rollback afterwards. Yields a balance reader."""
    rules = tmp_path / "rules.yaml"
    rules.write_text(f'auto_limit: "50"\nmax_tx: "500"\ndaily_cap: "1000"\n'
                     f'velocity: {{max_actions: 5, window_seconds: 600}}\ntrusted_origins: [user_chat]\n'
                     f'chain_id: null\nallowlist: ["{ALICE}"]\n')
    monkeypatch.setenv("RULES_PATH", str(rules))
    monkeypatch.setenv("APPROVAL_SECRET", "live-test-secret-0123456789abcdef")
    protected._PENDING.clear()
    api._PENDING_CONFIRMATIONS.clear()
    w3 = chain.get_web3()
    snapshot = w3.provider.make_request("evm_snapshot", [])["result"]
    token = erc20.token_contract(w3, chain.token_address())
    yield lambda address: token.functions.balanceOf(address).call()
    w3.provider.make_request("evm_revert", [snapshot])


def intent(action, token, to, amount, unlimited=False):
    """What a real model returns: the token as a SYMBOL, not an address."""
    return {"action": action, "token": token, "to": to, "amount": amount, "unlimited": unlimited, "rationale": "test"}


def says(monkeypatch, module, the_intent):
    """Fake only the LLM."""
    if module is naive:
        monkeypatch.setattr(naive, "parse_intent", lambda text, **kw: the_intent)
    else:
        monkeypatch.setattr(protected, "parse_intent", lambda text, **kw: the_intent)


# =============================== the naive agent (the one that loses) ===============================

def test_naive_agent_sends_when_the_llm_names_the_token_by_symbol(env, monkeypatch):
    before = env(ALICE)
    says(monkeypatch, naive, intent("transfer", "TUSD", ALICE, "5"))
    reply = naive.handle_message("send 5 TUSD to Alice's address")
    assert reply.blocked is False and reply.tx_hash and reply.tx_hash.startswith("0x")
    assert env(ALICE) == before + 5 * ONE


def test_naive_agent_is_drained_after_it_signs_an_unlimited_approval(env, monkeypatch):
    """The attack replay: an injected public post makes the naive agent approve UNLIMITED, then the attacker drains it."""
    victim = chain.wallet_address()
    before = env(victim)
    says(monkeypatch, naive, intent("approve", "TUSD", drainer.attacker_address(), "0", True))
    reply = naive.handle_message("(text of a public post)", origin="public_feed")
    assert reply.blocked is False and reply.tx_hash
    assert wallet_engine.approvals()[0]["allowance"] == "unlimited"
    result = drainer.drain("100")
    assert result.amount == "100"
    assert env(victim) == before - 100 * ONE


def test_naive_agent_gives_friendly_messages(env, monkeypatch):
    for the_intent, expected in [
        (intent("transfer", "TUSD", "Alice", "5"), "full 0x address"),
        (intent("transfer", "DOGE", ALICE, "5"), "don't know the token"),
        (intent("transfer", "ETH", ALICE, "5"), "only moves TUSD"),
        (intent("transfer", "TUSD", ALICE, "0.0000000000000000001"), "Too many decimal places"),
    ]:
        says(monkeypatch, naive, the_intent)
        reply = naive.handle_message("x")
        assert reply.blocked is True and expected in reply.text, reply.text
        assert "Error" not in reply.text                                  # no "(ValueError)" gibberish


# =============================== the protected agent ===============================

def test_protected_agent_allows_an_allowlisted_transfer(env, monkeypatch):
    before = env(ALICE)
    says(monkeypatch, protected, intent("transfer", "TUSD", ALICE, "10"))
    reply = protected.handle_message("send 10 TUSD to Alice's address")
    assert reply.decision.decision == "allow" and reply.tx_hash and reply.blocked is False
    assert env(ALICE) == before + 10 * ONE


def test_protected_agent_denies_the_same_text_from_a_public_post(env, monkeypatch):
    before = env(ALICE)
    says(monkeypatch, protected, intent("transfer", "TUSD", ALICE, "10"))
    reply = protected.handle_message("(text of a public post)", origin="public_feed")
    assert reply.decision.decision == "deny" and "PRV-01" in reply.decision.rule_ids
    assert reply.blocked is True and reply.tx_hash is None
    assert env(ALICE) == before


def test_protected_agent_asks_then_sends_after_confirmation_only_once(env, monkeypatch):
    before = env(CAFE)
    says(monkeypatch, protected, intent("transfer", "TUSD", CAFE, "10"))
    reply = protected.handle_message("send 10 TUSD to a new address")
    assert reply.decision.decision == "ask" and reply.tx_hash is None and "Nothing has been sent" in reply.text
    assert env(CAFE) == before
    confirmed = protected.confirm_pending(reply.decision.request_id)
    assert confirmed.decision.decision == "allow" and confirmed.tx_hash
    assert env(CAFE) == before + 10 * ONE
    again = protected.confirm_pending(reply.decision.request_id)
    assert again.blocked is True and again.tx_hash is None
    assert env(CAFE) == before + 10 * ONE                                 # not paid twice


def test_protected_agent_denies_an_unlimited_approval(env, monkeypatch):
    says(monkeypatch, protected, intent("approve", "TUSD", ALICE, "0", True))
    reply = protected.handle_message("approve unlimited")
    assert reply.decision.decision == "deny" and "APR-01" in reply.decision.rule_ids
    assert reply.tx_hash is None and wallet_engine.approvals() == []


def test_protected_agent_explains_what_is_wrong_with_the_request(env, monkeypatch):
    for the_intent, expected in [
        (intent("transfer", "TUSD", "Alice", "10"), "full 0x address"),
        (intent("transfer", "TUSD", ALICE[:12], "10"), "full 0x address"),
        (intent("transfer", "DOGE", ALICE, "10"), "don't know the token"),
    ]:
        says(monkeypatch, protected, the_intent)
        reply = protected.handle_message("x")
        assert reply.blocked is True and expected in reply.text and reply.tx_hash is None, reply.text
    assert state.actions_in_window() == 0          # refused before the firewall was even asked


# =============================== the API ===============================

BODY = {"action": "transfer", "to": ALICE, "amount": "10"}


def test_previews_change_nothing(env):
    for _ in range(8):                                                     # more than the 5-actions limit
        reply = client.post("/api/plan", json=BODY)
        assert reply.status_code == 200
        assert reply.json()["decision"]["decision"] == "allow"
        assert reply.json()["decision"]["approval_token"] is None
    assert state.actions_in_window() == 0 and state.spent_last_24h() == 0
    assert api._PENDING_CONFIRMATIONS == {} and policy._PENDING == {}
    assert audit.check().entries == 0


def test_preview_then_execute_is_counted_exactly_once(env):
    before = env(ALICE)
    for _ in range(3):
        client.post("/api/plan", json=BODY)
    executed = client.post("/api/execute", json=BODY).json()
    assert executed["status"] == "executed" and executed["tx_hash"]
    assert state.actions_in_window() == 1
    assert state.spent_last_24h() == 10
    assert env(ALICE) == before + 10 * ONE
    # and a harmless transfer is still allowed afterwards (it used to turn into "ask" after 3 rounds)
    assert client.post("/api/plan", json=BODY).json()["decision"]["decision"] == "allow"


def test_execute_of_an_ask_needs_a_separate_confirm(env):
    before = env(CAFE)
    body = {"action": "transfer", "to": CAFE, "amount": "10"}
    preview = client.post("/api/plan", json=body).json()
    assert preview["decision"]["decision"] == "ask"
    # the id shown by a preview can NOT be confirmed: only Execute opens the question
    assert client.post("/api/confirm", json={"request_id": preview["request"]["request_id"]}).status_code == 404
    asked = client.post("/api/execute", json=body).json()
    assert asked["status"] == "awaiting_confirmation" and asked["tx_hash"] is None
    assert env(CAFE) == before
    sent = client.post("/api/confirm", json={"request_id": asked["request_id"]}).json()
    assert sent["status"] == "executed" and sent["tx_hash"]
    assert env(CAFE) == before + 10 * ONE
    assert client.post("/api/confirm", json={"request_id": asked["request_id"]}).status_code == 404   # single use


def test_execute_is_denied_for_an_unlimited_approval(env):
    reply = client.post("/api/execute", json={"action": "approve", "to": ALICE, "amount": "0", "unlimited": True}).json()
    assert reply["status"] == "denied" and reply["tx_hash"] is None
    assert wallet_engine.approvals() == []


def test_a_browser_supplied_decision_is_ignored(env):
    before = env(ALICE)
    forged = dict(BODY, amount="600", decision={"decision": "allow", "approval_token": "forged"})
    reply = client.post("/api/execute", json=forged).json()
    assert reply["status"] == "denied" and "LIM-01" in reply["decision"]["rule_ids"]
    assert env(ALICE) == before
