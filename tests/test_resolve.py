"""agent/resolve.py: symbol -> token address and 0x-address checks, shared by BOTH agents. Offline."""
from types import SimpleNamespace

import pytest
from web3 import Web3

from agent import resolve
from agent.resolve import UserInputError, require_address, resolve_token

ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
TOKEN = "0x5FbDB2315678afecb367f032d93F642f64180aa3"


# ---- addresses ----
@pytest.mark.parametrize("good", [ALICE, ALICE.lower(), "0x" + ALICE[2:].upper(), "  " + ALICE + " "])
def test_valid_addresses_are_accepted(good):
    assert require_address(good, "transfer") == good.strip()


@pytest.mark.parametrize("bad", ["Alice", "", "   ", None, 123, ALICE[:20], ALICE + "00", "0x" + "zz" * 20, ALICE[2:]])
def test_names_short_and_malformed_addresses_are_refused(bad):
    with pytest.raises(UserInputError, match="full 0x address"):
        require_address(bad, "transfer")


def test_the_message_names_the_role():
    with pytest.raises(UserInputError, match="recipient"):
        require_address("Alice", "transfer")
    for action in ("approve", "revoke"):
        with pytest.raises(UserInputError, match="spender"):
            require_address("Alice", action)


def test_a_mistyped_mixed_case_address_is_caught_by_its_checksum():
    typo = ALICE[:-1] + ("D" if ALICE[-1] != "D" else "E")             # change one letter, keep the mixed case
    assert Web3.is_checksum_address(ALICE) and not Web3.is_checksum_address(typo)
    with pytest.raises(UserInputError, match="mistyped"):
        require_address(typo, "transfer")


# ---- tokens ----
@pytest.fixture
def configured(monkeypatch):
    contract = SimpleNamespace(functions=SimpleNamespace(symbol=lambda: SimpleNamespace(call=lambda: "TUSD")))
    monkeypatch.setattr(resolve.chain, "get_web3", lambda: object())
    monkeypatch.setattr(resolve.chain, "token_address", lambda: TOKEN)
    monkeypatch.setattr(resolve.erc20, "token_contract", lambda w3, address: contract)


@pytest.mark.parametrize("symbol", ["TUSD", "tusd", " Tusd "])
def test_the_configured_symbol_becomes_the_contract_address(configured, symbol):
    assert resolve_token(symbol) == TOKEN


def test_an_address_is_passed_through_without_asking_the_chain(monkeypatch):
    monkeypatch.setattr(resolve.chain, "get_web3", lambda: pytest.fail("the chain must not be needed"))
    assert resolve_token(TOKEN) == TOKEN


@pytest.mark.parametrize("token, message", [
    ("DOGE", "don't know the token 'DOGE'"),
    ("ETH", "only moves TUSD"),
    ("eth", "only moves TUSD"),
    ("", "which token"),
    ("   ", "which token"),
    (None, "which token"),
])
def test_unknown_or_unsupported_tokens_are_refused_in_plain_english(configured, token, message):
    with pytest.raises(UserInputError, match=message):
        resolve_token(token)
