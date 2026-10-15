"""The attack-replay drainer (Person 1, issue #10). LOCAL CHAIN ONLY.

Offline tests always run and prove the safety refusals. Live tests need a local Anvil with
TestUSD deployed (`anvil`, then `python wallet_engine/scripts/deploy.py`); they skip themselves
otherwise and are rolled back with evm_snapshot / evm_revert.
"""
import os
from types import SimpleNamespace

import pytest

import wallet_engine
from shared.types import ActionRequest, Decision
from wallet_engine import chain, erc20
from wallet_engine.attacks import drainer
from wallet_engine.attacks.drainer import DrainRefused, drain

MAX_UINT = 2**256 - 1
ONE = 10**18


def _fake_web3(chain_id):
    """A stand-in node that reports a chain id; any other use would raise AttributeError."""
    return SimpleNamespace(is_connected=lambda: True, eth=SimpleNamespace(chain_id=chain_id))


# =============================== offline: the safety limits ===============================

def test_refuses_when_network_is_not_local(monkeypatch):
    monkeypatch.setenv("ACTIVE_NETWORK", "sepolia")

    def boom():
        raise AssertionError("must refuse BEFORE touching any node")
    monkeypatch.setattr(chain, "get_web3", boom)
    with pytest.raises(DrainRefused, match="local chain only"):
        drain()


def test_refuses_when_chain_id_is_not_31337(monkeypatch):
    monkeypatch.setenv("ACTIVE_NETWORK", "local")
    for other in (1, 11155111, 8453):
        monkeypatch.setattr(chain, "get_web3", lambda other=other: _fake_web3(other))
        with pytest.raises(DrainRefused, match="not the local chain"):
            drain()


def test_refuses_without_a_node(monkeypatch):
    monkeypatch.setenv("ACTIVE_NETWORK", "local")
    monkeypatch.setenv("RPC_URL_LOCAL", "http://127.0.0.1:1")      # nothing listens here
    with pytest.raises(DrainRefused, match="Cannot reach"):
        drain()


def test_refuses_without_attacker_key(monkeypatch):
    monkeypatch.setenv("ACTIVE_NETWORK", "local")
    monkeypatch.setattr(chain, "get_web3", lambda: _fake_web3(31337))
    monkeypatch.delenv("ATTACKER_PRIVATE_KEY", raising=False)
    with pytest.raises(DrainRefused, match="ATTACKER_PRIVATE_KEY"):
        drain()
    with pytest.raises(DrainRefused, match="ATTACKER_PRIVATE_KEY"):
        drainer.attacker_address()


def test_never_returns_or_prints_the_key(monkeypatch, capsys):
    secret = "0x" + "ab" * 32
    monkeypatch.setenv("ATTACKER_PRIVATE_KEY", secret)
    monkeypatch.setenv("ACTIVE_NETWORK", "sepolia")
    assert drainer.main(["drainer"]) == 1
    out = capsys.readouterr().out
    assert secret not in out and "ab" * 32 not in out and "REFUSED" in out


# =============================== live (local anvil) ===============================

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
def env(live):
    """(w3, token, victim_account, attacker_address); all changes are rolled back afterwards."""
    w3 = chain.get_web3()
    snap = w3.provider.make_request("evm_snapshot", [])["result"]
    token = erc20.token_contract(w3, chain.token_address())
    victim = w3.eth.account.from_key(os.environ["WALLET_PRIVATE_KEY"])
    yield w3, token, victim, drainer.attacker_address()
    w3.provider.make_request("evm_revert", [snap])


def _approve(w3, token, victim, spender, value):
    """The victim grants an allowance (what a tricked wallet would do)."""
    tx = token.functions.approve(spender, value).build_transaction(
        {"from": victim.address, "nonce": w3.eth.get_transaction_count(victim.address), "chainId": w3.eth.chain_id})
    h = w3.eth.send_raw_transaction(victim.sign_transaction(tx).raw_transaction)
    assert w3.eth.wait_for_transaction_receipt(h).status == 1


def test_drain_works_with_an_unlimited_allowance(env):
    w3, token, victim, attacker = env
    _approve(w3, token, victim, attacker, MAX_UINT)
    v0, a0 = token.functions.balanceOf(victim.address).call(), token.functions.balanceOf(attacker).call()

    r = drain("25")

    assert r.amount == "25" and r.tx_hash.startswith("0x") and len(r.tx_hash) == 66
    assert w3.eth.get_transaction_receipt(r.tx_hash).status == 1
    assert token.functions.balanceOf(victim.address).call() == v0 - 25 * ONE
    assert token.functions.balanceOf(attacker).call() == a0 + 25 * ONE
    assert r.allowance_after == "unlimited"                       # never used up...
    assert drain("5").amount == "5"                               # ...so it can be repeated
    assert token.functions.balanceOf(victim.address).call() == v0 - 30 * ONE


def test_drain_without_amount_takes_everything(env):
    w3, token, victim, attacker = env
    _approve(w3, token, victim, attacker, MAX_UINT)
    v0 = token.functions.balanceOf(victim.address).call()
    r = drain()
    assert r.victim_after == "0"
    assert token.functions.balanceOf(victim.address).call() == 0
    assert r.amount == erc20.from_base_units(v0)
    with pytest.raises(DrainRefused, match="no tokens"):
        drain()


def test_a_limited_allowance_limits_the_damage(env):
    w3, token, victim, attacker = env
    _approve(w3, token, victim, attacker, 5 * ONE)
    v0 = token.functions.balanceOf(victim.address).call()
    with pytest.raises(DrainRefused, match="exceeds the allowance"):
        drain("6")
    assert token.functions.balanceOf(victim.address).call() == v0       # nothing moved
    r = drain()                                                        # default = min(allowance, balance)
    assert r.amount == "5" and r.allowance_after == "0"
    with pytest.raises(DrainRefused, match="no allowance"):
        drain()
    assert token.functions.balanceOf(victim.address).call() == v0 - 5 * ONE


def test_no_allowance_means_nothing_to_drain(env):
    w3, token, victim, attacker = env
    v0 = token.functions.balanceOf(victim.address).call()
    attacker_nonce = w3.eth.get_transaction_count(attacker)
    with pytest.raises(DrainRefused, match="no allowance"):
        drain()
    assert token.functions.balanceOf(victim.address).call() == v0
    assert w3.eth.get_transaction_count(attacker) == attacker_nonce    # no transaction was even sent


def test_revoking_stops_the_drain(env):
    w3, token, victim, attacker = env
    _approve(w3, token, victim, attacker, MAX_UINT)
    _approve(w3, token, victim, attacker, 0)                          # revoke
    with pytest.raises(DrainRefused, match="no allowance"):
        drain()


@pytest.mark.parametrize("bad", ["0", "-1", "abc", "", "0.0000000000000000001"])
def test_rejects_bad_amounts(env, bad):
    w3, token, victim, attacker = env
    _approve(w3, token, victim, attacker, MAX_UINT)
    v0 = token.functions.balanceOf(victim.address).call()
    with pytest.raises(DrainRefused):
        drain(bad)
    assert token.functions.balanceOf(victim.address).call() == v0


def test_amount_larger_than_balance_is_refused(env):
    w3, token, victim, attacker = env
    _approve(w3, token, victim, attacker, MAX_UINT)
    with pytest.raises(DrainRefused, match="exceeds the victim's balance"):
        drain("5000000")


def test_the_demo_story_naive_wallet_signs_the_approval_then_loses_funds(env, monkeypatch):
    """What the attack replay shows: an agent with no firewall signs an UNLIMITED approval
    because an injected message asked it to, then the attacker drains it. Revoking ends it."""
    w3, token, victim, attacker = env
    import firewall.tokens as ft
    monkeypatch.setattr(ft, "verify_token", lambda *a, **k: True)      # naive path: no real check
    allow = Decision(request_id="demo", decision="allow", approval_token="x")

    def run(action, amount="0", unlimited=False):
        req = ActionRequest("demo", action, chain.token_address(), attacker, amount, unlimited, "public_feed")
        return wallet_engine.execute(wallet_engine.plan(req), allow)

    v0 = token.functions.balanceOf(victim.address).call()
    run("approve", unlimited=True)                                     # the mistake
    assert wallet_engine.approvals()[0]["allowance"] == "unlimited"
    r = drain("100")                                                   # the theft
    assert token.functions.balanceOf(victim.address).call() == v0 - 100 * ONE
    assert r.attacker_after == erc20.from_base_units(token.functions.balanceOf(attacker).call())
    run("revoke")                                                      # the remedy
    with pytest.raises(DrainRefused, match="no allowance"):
        drain()
