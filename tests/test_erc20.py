"""erc20.py / chain.py (Person 1). Offline tests always run; chain tests skip without anvil."""
import os

import pytest
from web3 import Web3

import wallet_engine
from shared.types import ActionRequest
from wallet_engine import chain, erc20

ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"   # anvil account #1 (public test address)


# ---------- offline ----------
@pytest.mark.parametrize("text, raw", [("1", 10**18), ("12.5", 125 * 10**17), ("0", 0), ("0.000000000000000001", 1)])
def test_to_base_units(text, raw):
    assert erc20.to_base_units(text) == raw


@pytest.mark.parametrize("bad", ["-1", "abc", "", "0.0000000000000000001"])
def test_to_base_units_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        erc20.to_base_units(bad)


def test_from_base_units():
    assert erc20.from_base_units(125 * 10**17) == "12.5"
    assert erc20.from_base_units(10**18) == "1"
    assert erc20.from_base_units(erc20.MAX_UINT256) == "unlimited"


def test_decode_roundtrip_offline():
    data = Web3().eth.contract(abi=erc20.ERC20_ABI).encode_abi("transfer", args=[ALICE, 10**18])
    function, args = erc20.decode(data)
    assert function == "transfer(address,uint256)"
    assert args == {"to": ALICE, "value": 10**18}


# ---------- live (local anvil) ----------
@pytest.fixture(scope="module")
def live():
    try:
        st = chain.status()
    except Exception:
        pytest.skip("chain not configured")
    if not st.get("connected") or st.get("chain_id") != 31337 or not st.get("token_deployed"):
        pytest.skip("local anvil with deployed TestUSD not available")
    return st


def _req(action, amount="10", unlimited=False):
    return ActionRequest("t1", action, os.environ["TOKEN_ADDRESS"], ALICE, amount, unlimited, "user_chat")


def test_plan_transfer(live):
    p = wallet_engine.plan(_req("transfer", "10"))
    assert p.function == "transfer(address,uint256)"
    assert p.args == {"to": ALICE, "value": 10 * 10**18}
    assert p.chain_id == 31337 and p.value == 0 and p.gas > 0
    assert "Send 10 TUSD" in p.summary


def test_plan_unlimited_approve_is_max_uint(live):
    p = wallet_engine.plan(_req("approve", "0", unlimited=True))
    assert p.args["value"] == erc20.MAX_UINT256
    assert "UNLIMITED" in p.summary


def test_plan_revoke_is_approve_zero(live):
    p = wallet_engine.plan(_req("revoke", "0"))
    assert p.function == "approve(address,uint256)" and p.args["value"] == 0


def test_balances_and_approvals(live):
    b = wallet_engine.balances()
    assert set(b) == {"ETH", "TUSD"}
    assert isinstance(wallet_engine.approvals(), list)
