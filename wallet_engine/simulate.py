"""Dry-run a transaction before sending it (Person 1, issue #8).

simulate.run(plan) asks the node "what would happen if we sent this?" using eth_call and
estimate_gas. Nothing is signed or sent. It NEVER raises: a problem is reported as ok=False
with a plain-English reason, so the firewall (rule SIM-01) can deny it.

The outflow and allowance are read from the CALLDATA that would really be signed
(see binding.py), not from plan.args or the original request. That is what lets the firewall
catch a plan whose transaction does not match what was asked.
"""
from web3 import Web3

from shared.types import SimResult, TxPlan

from . import chain, erc20
from .binding import token_binding


def _fail(reason: str) -> SimResult:
    return SimResult(ok=False, revert_reason=reason, outflow="0", allowance_after=None)


def _revert_reason(exc: Exception) -> str:
    """Make a node error readable: 'execution reverted: TestUSD: insufficient balance' -> 'TestUSD: insufficient balance'."""
    text = getattr(exc, "message", None) or str(exc)
    text = text.strip()
    for prefix in ("execution reverted: ", "execution reverted"):
        if text.lower().startswith(prefix):
            text = text[len(prefix):].strip()
            break
    return text or "The transaction would revert"


def run(plan: TxPlan) -> SimResult:
    try:
        return _run(plan)
    except Exception as exc:   # a simulation must report, never crash the caller
        return _fail(f"Simulation error: {type(exc).__name__}: {_revert_reason(exc)}")


def _run(plan: TxPlan) -> SimResult:
    w3 = chain.get_web3()
    if not w3.is_connected():
        return _fail("Cannot reach the blockchain node")

    node_chain = w3.eth.chain_id
    if plan.chain_id != node_chain:
        return _fail(f"Wrong network: the plan is for chain {plan.chain_id} but the node is chain {node_chain}")
    if plan.value != 0:
        return _fail("Plain ETH transfers are not supported (value must be 0)")

    binding = token_binding(plan)   # ValueError (unsupported / malformed calldata) is handled by run()

    contract_addr = Web3.to_checksum_address(plan.to)
    if not w3.eth.get_code(contract_addr):
        return _fail("The target address is not a contract")

    tx = {"from": Web3.to_checksum_address(plan.from_addr), "to": contract_addr, "data": plan.data, "value": 0}
    try:
        w3.eth.call(tx)                 # would it revert?
        gas = w3.eth.estimate_gas(tx)   # how much gas would it use?
    except Exception as exc:
        return _fail(_revert_reason(exc))

    gas_needed = gas * w3.eth.gas_price
    if w3.eth.get_balance(tx["from"]) < gas_needed:
        return _fail("Not enough ETH in the wallet to pay for gas")

    decimals = erc20.token_contract(w3, contract_addr).functions.decimals().call()
    amount = erc20.from_base_units(int(binding["amount"]), decimals)
    if binding["action"] == "transfer":
        return SimResult(ok=True, revert_reason=None, outflow=amount, allowance_after=None)
    # approve / revoke: no tokens leave now; report the allowance that would exist afterwards
    return SimResult(ok=True, revert_reason=None, outflow="0", allowance_after=amount)
