"""simulate() and execute() (Person 1, issues #8 and #9).

Offline tests always run. Live tests need a local Anvil with TestUSD deployed
(`anvil`, then `python wallet_engine/scripts/deploy.py`); they skip themselves otherwise,
and they run on the local chain only. Every live test is rolled back with evm_snapshot/evm_revert.

execute() tests replace firewall.tokens.verify_token with a small fake that binds to the
transaction fields, so they keep working when Person 2 replaces the stub with the real HMAC.
"""
import os
from types import SimpleNamespace

import pytest
from web3 import Web3

import wallet_engine
from shared.types import ActionRequest, Decision, TxPlan
from wallet_engine import chain, erc20
from wallet_engine.binding import token_binding
from wallet_engine.execute import ExecutionRefused

ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"          # anvil account #1 (public test address)
TOKEN_FAKE = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
WALLET_FAKE = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ONE = 10**18


def _calldata(fn: str, to: str, value: int) -> str:
    return Web3().eth.contract(abi=erc20.ERC20_ABI).encode_abi(fn, args=[Web3.to_checksum_address(to), value])


def _plan(fn="transfer", to=ALICE, value=10 * ONE, **overrides) -> TxPlan:
    base = dict(chain_id=31337, from_addr=WALLET_FAKE, to=TOKEN_FAKE, value=0, data=_calldata(fn, to, value),
                gas=60_000, function=f"{fn}(address,uint256)", args={}, summary="test")
    base.update(overrides)
    return TxPlan(**base)


def _decision(decision="allow", token="GOOD", request_id="req-1") -> Decision:
    return Decision(request_id=request_id, decision=decision, approval_token=token)


class FakeTokens:
    """Stands in for firewall.tokens: accepts a token only for the exact fields it was issued for."""

    def __init__(self, issued_for: dict | None):
        self.issued_for = issued_for
        self.calls = []

    def verify_token(self, approval_token, request_id, action, token_addr, to, amount):
        self.calls.append(dict(approval_token=approval_token, request_id=request_id, action=action,
                               token=token_addr, to=to, amount=amount))
        return self.issued_for is not None and approval_token == "GOOD" and self.issued_for == dict(
            action=action, token=token_addr, to=to, amount=amount)


@pytest.fixture
def fake_tokens(monkeypatch):
    import firewall.tokens as real

    def install(issued_for):
        fake = FakeTokens(issued_for)
        monkeypatch.setattr(real, "verify_token", fake.verify_token)
        return fake
    return install


# =============================== offline ===============================

def test_binding_transfer():
    b = token_binding(_plan("transfer", ALICE, 10 * ONE))
    assert b == {"action": "transfer", "token": TOKEN_FAKE.lower(), "to": ALICE.lower(), "amount": str(10 * ONE)}


def test_binding_approve_revoke_unlimited():
    assert token_binding(_plan("approve", ALICE, 5 * ONE))["action"] == "approve"
    assert token_binding(_plan("approve", ALICE, 0))["action"] == "revoke"
    unlimited = token_binding(_plan("approve", ALICE, erc20.MAX_UINT256))
    assert unlimited["action"] == "approve" and unlimited["amount"] == str(2**256 - 1)


@pytest.mark.parametrize("data", ["", "0x", "0xdeadbeef", "xyz", "0xa9059cbb" + "00" * 10,
                                  "0xa9059cbb" + "ff" * 64, "0xa9059cbb" + "zz" * 64])
def test_binding_rejects_bad_calldata(data):
    with pytest.raises(ValueError):
        token_binding(_plan(data=data))


def test_execute_refuses_non_allow_decisions():
    for state in ("deny", "ask", "banana", None):
        with pytest.raises(ExecutionRefused):
            wallet_engine.execute(_plan(), SimpleNamespace(decision=state, approval_token="GOOD", request_id="r"))


def test_execute_refuses_missing_token():
    for token in (None, ""):
        with pytest.raises(ExecutionRefused, match="No approval token"):
            wallet_engine.execute(_plan(), _decision(token=token))


def test_execute_refuses_unsupported_transaction():
    with pytest.raises(ExecutionRefused, match="Unsupported"):
        wallet_engine.execute(_plan(data="0xdeadbeef"), _decision())


def test_execute_passes_the_calldata_fields_to_verify_token(fake_tokens):
    plan = _plan("transfer", ALICE, 7 * ONE)
    fake = fake_tokens(issued_for=None)             # reject, but record what was asked
    with pytest.raises(ExecutionRefused):
        wallet_engine.execute(plan, _decision(request_id="abc"))
    assert fake.calls == [dict(approval_token="GOOD", request_id="abc", action="transfer",
                               token=TOKEN_FAKE.lower(), to=ALICE.lower(), amount=str(7 * ONE))]


def test_execute_refuses_token_issued_for_a_different_amount(fake_tokens):
    issued = token_binding(_plan("transfer", ALICE, 1 * ONE))
    fake_tokens(issued_for=issued)
    with pytest.raises(ExecutionRefused, match="does not match"):
        wallet_engine.execute(_plan("transfer", ALICE, 1000 * ONE), _decision())     # approve 1, send 1000


def test_execute_refuses_token_issued_for_a_different_recipient(fake_tokens):
    issued = token_binding(_plan("transfer", ALICE, 1 * ONE))
    fake_tokens(issued_for=issued)
    other = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
    with pytest.raises(ExecutionRefused, match="does not match"):
        wallet_engine.execute(_plan("transfer", other, 1 * ONE), _decision())


def test_simulate_without_a_node_does_not_raise(monkeypatch):
    monkeypatch.setenv("ACTIVE_NETWORK", "local")
    monkeypatch.setenv("RPC_URL_LOCAL", "http://127.0.0.1:1")      # nothing listens here
    sim = wallet_engine.simulate(_plan())
    assert sim.ok is False and sim.revert_reason


def test_execute_without_a_node_refuses_cleanly(monkeypatch, fake_tokens):
    monkeypatch.setenv("ACTIVE_NETWORK", "local")
    monkeypatch.setenv("RPC_URL_LOCAL", "http://127.0.0.1:1")
    monkeypatch.setenv("WALLET_PRIVATE_KEY", "0x" + "11" * 32)       # throwaway value, never used on a chain
    plan = _plan()
    fake_tokens(issued_for=token_binding(plan))
    with pytest.raises(ExecutionRefused, match="Cannot reach"):
        wallet_engine.execute(plan, _decision())


# =============================== live (local anvil) ===============================

@pytest.fixture(scope="module")
def live():
    try:
        st = chain.status()
    except Exception:
        pytest.skip("chain not configured")
    if not st.get("connected") or st.get("chain_id") != 31337 or not st.get("token_deployed"):
        pytest.skip("local anvil with deployed TestUSD not available")
    return st


@pytest.fixture
def chain_env(live):
    """Yield (w3, token_contract, owner_address, tokens_address); roll back all changes afterwards."""
    w3 = chain.get_web3()
    snap = w3.provider.make_request("evm_snapshot", [])["result"]
    token = erc20.token_contract(w3, chain.token_address())
    yield w3, token, chain.wallet_address(), chain.token_address()
    w3.provider.make_request("evm_revert", [snap])


def _req(action, amount="10", unlimited=False, to=ALICE):
    return ActionRequest("t1", action, os.environ["TOKEN_ADDRESS"], to, amount, unlimited, "user_chat")


# ---- simulate ----

def test_simulate_transfer(chain_env):
    sim = wallet_engine.simulate(wallet_engine.plan(_req("transfer", "10")))
    assert (sim.ok, sim.revert_reason, sim.outflow, sim.allowance_after) == (True, None, "10", None)


def test_simulate_approve_and_revoke_and_unlimited(chain_env):
    sim = wallet_engine.simulate(wallet_engine.plan(_req("approve", "5")))
    assert (sim.ok, sim.outflow, sim.allowance_after) == (True, "0", "5")
    sim = wallet_engine.simulate(wallet_engine.plan(_req("approve", "0", unlimited=True)))
    assert (sim.ok, sim.allowance_after) == (True, "unlimited")
    sim = wallet_engine.simulate(wallet_engine.plan(_req("revoke", "0")))
    assert (sim.ok, sim.allowance_after) == (True, "0")


def test_simulate_over_balance_reports_the_contract_reason(chain_env):
    sim = wallet_engine.simulate(wallet_engine.plan(_req("transfer", "2000000")))
    assert sim.ok is False and "insufficient balance" in sim.revert_reason and sim.outflow == "0"


def test_simulate_reads_outflow_from_calldata_not_from_args(chain_env):
    plan = wallet_engine.plan(_req("transfer", "10"))
    plan.args = {"to": ALICE, "value": 1}            # a lying description
    assert wallet_engine.simulate(plan).outflow == "10"


def test_simulate_rejects_wrong_chain_non_contract_value_and_junk(chain_env):
    plan = wallet_engine.plan(_req("transfer", "10"))
    cases = {
        "Wrong network": TxPlan(**{**plan.__dict__, "chain_id": 1}),
        "not a contract": TxPlan(**{**plan.__dict__, "to": ALICE}),
        "Plain ETH": TxPlan(**{**plan.__dict__, "value": 1}),
        "unsupported function": TxPlan(**{**plan.__dict__, "data": "0xdeadbeef"}),
    }
    for expected, bad in cases.items():
        sim = wallet_engine.simulate(bad)
        assert sim.ok is False and expected in sim.revert_reason, expected


def test_simulate_reports_missing_gas_money(chain_env, fake_tokens):
    w3, token, owner, token_addr = chain_env
    broke = w3.eth.account.create()
    give = wallet_engine.plan(_req("transfer", "5", to=broke.address))     # broke gets 5 TUSD but no ETH
    fake_tokens(issued_for=token_binding(give))
    wallet_engine.execute(give, _decision())
    assert w3.eth.get_balance(broke.address) == 0
    own = wallet_engine.plan(_req("transfer", "1"))
    own = TxPlan(**{**own.__dict__, "from_addr": broke.address})
    sim = wallet_engine.simulate(own)
    assert sim.ok is False and "gas" in sim.revert_reason.lower()


# ---- execute ----

def _allowing(fake_tokens, plan):
    return fake_tokens(issued_for=token_binding(plan))


def test_execute_sends_a_real_transfer(chain_env, fake_tokens):
    w3, token, owner, _ = chain_env
    plan = wallet_engine.plan(_req("transfer", "10"))
    _allowing(fake_tokens, plan)
    before = token.functions.balanceOf(ALICE).call()
    tx_hash = wallet_engine.execute(plan, _decision())
    assert tx_hash.startswith("0x") and len(tx_hash) == 66
    assert w3.eth.get_transaction_receipt(tx_hash).status == 1
    assert token.functions.balanceOf(ALICE).call() == before + 10 * ONE


def test_execute_approve_then_revoke(chain_env, fake_tokens):
    w3, token, owner, _ = chain_env
    approve = wallet_engine.plan(_req("approve", "5"))
    _allowing(fake_tokens, approve)
    wallet_engine.execute(approve, _decision())
    assert token.functions.allowance(owner, ALICE).call() == 5 * ONE
    assert wallet_engine.approvals()[0]["allowance"] == "5"
    revoke = wallet_engine.plan(_req("revoke", "0"))
    _allowing(fake_tokens, revoke)
    wallet_engine.execute(revoke, _decision())
    assert token.functions.allowance(owner, ALICE).call() == 0


def test_execute_refusals_send_nothing(chain_env, fake_tokens):
    w3, token, owner, _ = chain_env
    nonce = w3.eth.get_transaction_count(owner)
    balance = token.functions.balanceOf(ALICE).call()
    plan = wallet_engine.plan(_req("transfer", "10"))

    # no token / deny / wrong token for the amount
    for decision in (_decision(token=None), _decision("deny"), _decision("ask")):
        with pytest.raises(ExecutionRefused):
            wallet_engine.execute(plan, decision)
    fake_tokens(issued_for=token_binding(wallet_engine.plan(_req("transfer", "1"))))
    with pytest.raises(ExecutionRefused, match="does not match"):
        wallet_engine.execute(plan, _decision())

    # token is fine, but the plan is for another wallet / chain / too much gas / would revert
    _allowing(fake_tokens, plan)
    bad_plans = {
        "not built for this wallet": TxPlan(**{**plan.__dict__, "from_addr": ALICE}),
        "Wrong network": TxPlan(**{**plan.__dict__, "chain_id": 1}),
        "Unreasonable gas": TxPlan(**{**plan.__dict__, "gas": 5_000_000}),
    }
    for expected, bad in bad_plans.items():
        with pytest.raises(ExecutionRefused, match=expected):
            wallet_engine.execute(bad, _decision())
    huge = wallet_engine.plan(_req("transfer", "2000000"))
    _allowing(fake_tokens, huge)
    with pytest.raises(ExecutionRefused, match="Simulation failed"):
        wallet_engine.execute(huge, _decision())

    assert w3.eth.get_transaction_count(owner) == nonce          # nothing was sent
    assert token.functions.balanceOf(ALICE).call() == balance


def test_executed_plan_cannot_be_swapped_after_approval(chain_env, fake_tokens):
    """Approve 1 TUSD, then try to send 1000: refused, and the balance does not move."""
    w3, token, owner, _ = chain_env
    approved = wallet_engine.plan(_req("transfer", "1"))
    swapped = wallet_engine.plan(_req("transfer", "1000"))
    _allowing(fake_tokens, approved)
    before = token.functions.balanceOf(ALICE).call()
    with pytest.raises(ExecutionRefused):
        wallet_engine.execute(swapped, _decision())
    assert token.functions.balanceOf(ALICE).call() == before
