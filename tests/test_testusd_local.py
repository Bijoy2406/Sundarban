"""TestUSD behaves like a standard ERC-20 on the LOCAL Anvil chain (Person 1).

Skipped automatically when anvil is not running or the token is not deployed.
Run:  anvil (terminal 1), then  python -m pytest -q  (terminal 2).
"""
import json
import os
from pathlib import Path

import pytest
from dotenv import load_dotenv
from web3 import Web3

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

MAX_UINT = 2**256 - 1
ONE = 10**18


def _connect():
    rpc = os.getenv("RPC_URL_LOCAL")
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 3})) if rpc else None
    if not w3 or not w3.is_connected():
        pytest.skip("local anvil not running")
    if w3.eth.chain_id != 31337:
        pytest.skip("not the local Anvil chain; these tests only run locally")
    return w3


@pytest.fixture(scope="module")
def env():
    w3 = _connect()
    token_addr = os.getenv("TOKEN_ADDRESS")
    if not token_addr or not w3.eth.get_code(Web3.to_checksum_address(token_addr)):
        pytest.skip("TestUSD not deployed; run wallet_engine/scripts/deploy.py")
    abi = json.loads((ROOT / "wallet_engine/out/TestUSD.sol/TestUSD.json").read_text())["abi"]
    token = w3.eth.contract(address=Web3.to_checksum_address(token_addr), abi=abi)
    owner = w3.eth.account.from_key(os.environ["WALLET_PRIVATE_KEY"])
    attacker = w3.eth.account.from_key(os.environ["ATTACKER_PRIVATE_KEY"])
    snap = w3.provider.make_request("evm_snapshot", [])["result"]   # undo our changes at the end
    yield w3, token, owner, attacker
    w3.provider.make_request("evm_revert", [snap])


def _send(w3, acct, fn):
    tx = fn.build_transaction({"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address),
                               "chainId": w3.eth.chain_id})
    h = w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction)
    return w3.eth.wait_for_transaction_receipt(h)


def test_metadata_and_supply(env):
    _, token, owner, _ = env
    assert token.functions.name().call() == "TestUSD"
    assert token.functions.symbol().call() == "TUSD"
    assert token.functions.decimals().call() == 18
    assert token.functions.totalSupply().call() == 1_000_000 * ONE
    assert token.functions.balanceOf(owner.address).call() <= 1_000_000 * ONE


def test_transfer_moves_tokens(env):
    w3, token, owner, attacker = env
    before = token.functions.balanceOf(attacker.address).call()
    assert _send(w3, owner, token.functions.transfer(attacker.address, 10 * ONE)).status == 1
    assert token.functions.balanceOf(attacker.address).call() == before + 10 * ONE


def test_transfer_over_balance_reverts(env):
    w3, token, owner, attacker = env
    broke = w3.eth.account.create()
    with pytest.raises(Exception):
        token.functions.transfer(owner.address, 1).call({"from": broke.address})


def test_limited_approval_is_consumed(env):
    w3, token, owner, attacker = env
    _send(w3, owner, token.functions.approve(attacker.address, 5 * ONE))
    assert token.functions.allowance(owner.address, attacker.address).call() == 5 * ONE
    _send(w3, attacker, token.functions.transferFrom(owner.address, attacker.address, 2 * ONE))
    assert token.functions.allowance(owner.address, attacker.address).call() == 3 * ONE


def test_unlimited_approval_is_never_used_up(env):
    """This is why APR-01 exists: an unlimited allowance lets a spender drain repeatedly."""
    w3, token, owner, attacker = env
    _send(w3, owner, token.functions.approve(attacker.address, MAX_UINT))
    _send(w3, attacker, token.functions.transferFrom(owner.address, attacker.address, 7 * ONE))
    assert token.functions.allowance(owner.address, attacker.address).call() == MAX_UINT


def test_revoke_stops_the_drain(env):
    w3, token, owner, attacker = env
    _send(w3, owner, token.functions.approve(attacker.address, MAX_UINT))
    _send(w3, owner, token.functions.approve(attacker.address, 0))          # revoke
    assert token.functions.allowance(owner.address, attacker.address).call() == 0
    with pytest.raises(Exception):
        token.functions.transferFrom(owner.address, attacker.address, 1).call({"from": attacker.address})
