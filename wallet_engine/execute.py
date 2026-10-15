"""Sign and send a transaction, but only with the firewall's valid approval (Person 1, issue #9).

execute.run(plan, decision) -> tx hash.

It refuses (raises ExecutionRefused, NOTHING is sent) unless ALL of these hold:
  1. the decision is "allow" and carries an approval token
  2. firewall.tokens.verify_token() accepts the token for the exact transaction that would be
     signed (action / token / recipient / amount are read from the CALLDATA, see binding.py)
  3. the plan is for the connected chain, from our own wallet, with value 0 and sane gas
  4. a fresh simulation right before sending still succeeds

The private key comes from .env (chain.key_var()) and is never logged or returned.
"""
import os

from web3 import Web3

from shared.types import Decision, TxPlan

from . import chain
from .binding import token_binding
from .simulate import run as simulate_run

MAX_GAS = 500_000          # refuse a plan that asks for an unreasonable gas limit
MIN_GAS = 21_000
RECEIPT_TIMEOUT = 120      # seconds to wait for the transaction to be mined


class ExecutionRefused(RuntimeError):
    """Nothing was sent. The message is safe to show to the user."""


class ExecutionFailed(RuntimeError):
    """The transaction was sent but failed on-chain (receipt status 0)."""


def _audit(event: dict) -> None:
    """Best effort: logging must never break (or hide) a transaction."""
    try:
        from firewall import audit
        audit.log(event)
    except Exception:
        pass


def _refuse(decision, reason: str):
    _audit({"event": "EXECUTE_REFUSED", "request_id": getattr(decision, "request_id", None), "reason": reason})
    raise ExecutionRefused(reason)


def _hex(value) -> str:
    text = value.hex()
    return text if text.startswith("0x") else "0x" + text


def _fee_fields(w3: Web3) -> dict:
    """EIP-1559 fees when the chain supports them, legacy gas price otherwise."""
    base = w3.eth.get_block("latest").get("baseFeePerGas")
    if base is None:
        return {"gasPrice": w3.eth.gas_price}
    priority = w3.eth.max_priority_fee
    return {"type": 2, "maxFeePerGas": int(base) * 2 + int(priority), "maxPriorityFeePerGas": int(priority)}


def run(plan: TxPlan, decision: Decision) -> str:
    # 1. the firewall must have said yes, and given proof
    if decision is None or decision.decision != "allow":
        state = getattr(decision, "decision", None)
        _refuse(decision, f"The firewall decision is '{state}', not 'allow'")
    if not decision.approval_token:
        _refuse(decision, "No approval token")

    # 2. the proof must match exactly what would be signed (read from the calldata)
    try:
        binding = token_binding(plan)
    except ValueError as exc:
        _refuse(decision, f"Unsupported transaction: {exc}")
    from firewall import tokens   # imported here to avoid a circular import at module load
    if not tokens.verify_token(decision.approval_token, decision.request_id, binding["action"],
                               binding["token"], binding["to"], binding["amount"]):
        _refuse(decision, "The approval token is invalid, expired, or does not match this transaction")

    # 3. sanity checks on the plan and the network
    key = os.getenv(chain.key_var())
    if not key:
        _refuse(decision, f"{chain.key_var()} is not set in .env")
    w3 = chain.get_web3()
    if not w3.is_connected():
        _refuse(decision, "Cannot reach the blockchain node")
    account = w3.eth.account.from_key(key)
    if plan.from_addr.lower() != account.address.lower():
        _refuse(decision, "The plan was not built for this wallet")
    if plan.chain_id != w3.eth.chain_id:
        _refuse(decision, f"Wrong network: plan is for chain {plan.chain_id}, node is chain {w3.eth.chain_id}")
    if plan.value != 0:
        _refuse(decision, "Plain ETH transfers are not supported")
    if not (MIN_GAS <= plan.gas <= MAX_GAS):
        _refuse(decision, f"Unreasonable gas limit {plan.gas}")

    # 4. simulate once more, right now (the chain may have changed since planning)
    sim = simulate_run(plan)
    if not sim.ok:
        _refuse(decision, f"Simulation failed: {sim.revert_reason}")

    # 5. sign and send
    tx = {
        "from": account.address,
        "to": Web3.to_checksum_address(plan.to),
        "data": plan.data,
        "value": 0,
        "gas": min(int(plan.gas * 1.2), MAX_GAS),
        "nonce": w3.eth.get_transaction_count(account.address, "pending"),
        "chainId": w3.eth.chain_id,
        **_fee_fields(w3),
    }
    signed = account.sign_transaction(tx)
    tx_hash = _hex(w3.eth.send_raw_transaction(signed.raw_transaction))
    _audit({"event": "TX_SENT", "request_id": decision.request_id, "tx_hash": tx_hash,
            "action": binding["action"], "token": binding["token"], "to": binding["to"], "amount": binding["amount"]})

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=RECEIPT_TIMEOUT)
    if receipt.status != 1:
        _audit({"event": "TX_FAILED", "request_id": decision.request_id, "tx_hash": tx_hash})
        raise ExecutionFailed(f"Transaction {tx_hash} was mined but failed")
    return tx_hash
