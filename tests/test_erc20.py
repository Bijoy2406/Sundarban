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


@pytest.mark.parametrize("text, raw", [
    ("1234567890123456789012345678901234567890", 1234567890123456789012345678901234567890 * 10**18),   # 40 digits
    ("1000000000000000000000000000.000000000000000001", 10**45 + 1),         # big integer part AND the 18th decimal
    ("9" * 100, int("9" * 100) * 10**18),
])
def test_to_base_units_is_exact_for_long_amounts(text, raw):
    """The default Decimal context keeps 28 digits and would round these silently (the encoded amount would be wrong)."""
    assert erc20.to_base_units(text) == raw


def test_an_amount_too_big_to_convert_exactly_is_refused_not_rounded():
    with pytest.raises(ValueError):
        erc20.to_base_units("1" + "2" * 299)


@pytest.mark.parametrize("raw", [2**255, 123456789012345678901234567890123456789012345, 10**60 + 1])
def test_from_base_units_is_exact_for_large_values(raw):
    from decimal import Context, Decimal, localcontext
    with localcontext(Context(prec=200)):
        exact = format(Decimal(raw) / Decimal(10) ** 18, "f").rstrip("0").rstrip(".")
    assert erc20.from_base_units(raw) == exact


def test_long_amounts_survive_a_round_trip():
    text = "1000000000000000000000000000.000000000000000001"
    assert erc20.from_base_units(erc20.to_base_units(text)) == text


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


@pytest.mark.parametrize("bad", [" 5", "5 ", "\u0665", "\uff15", "1e3", "1E-3", "NaN", "Infinity", "-0", "+5", "05", ".5", "5.", "1_0", "0x10", None, 5, 5.0])
def test_to_base_units_accepts_only_the_plain_decimal_pattern_the_agent_uses(bad):
    """Same rule as agent/intents.py: no spaces, signs, exponents, NaN/Infinity, leading zeros or non-ASCII digits.
    Everything is a clean ValueError (never InvalidOperation or OverflowError)."""
    with pytest.raises(ValueError):
        erc20.to_base_units(bad)


@pytest.mark.parametrize("text, raw", [("0", 0), ("0.5", 5 * 10**17), ("10", 10 * 10**18), ("100.000000000000000001", 100 * 10**18 + 1)])
def test_to_base_units_still_takes_plain_amounts(text, raw):
    assert erc20.to_base_units(text) == raw
