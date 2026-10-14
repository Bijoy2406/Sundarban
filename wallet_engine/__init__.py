"""Wallet engine facade (Person 1 owns this folder).

REAL:  plan(), balances(), approvals()   -> chain.py / erc20.py (read-only, nothing is sent)
STUB:  simulate(), execute()             -> Person 1 tasks 5 and 6 (simulate.py, execute.py)
SIGNATURES must not change (tests/test_contract.py checks them).
"""
from shared.types import ActionRequest, Decision, SimResult, TxPlan

from . import chain, erc20


def plan(req: ActionRequest) -> TxPlan:
    """Build the exact transaction for an ActionRequest. Nothing is signed or sent."""
    return erc20.plan(chain.get_web3(), req, chain.wallet_address())


def simulate(plan: TxPlan) -> SimResult:
    """STUB: always ok. Real version: eth_call + estimate_gas (Person 1, task 5)."""
    return SimResult(ok=True, revert_reason=None, outflow=str(plan.args.get("value", "0")), allowance_after=None)


def execute(plan: TxPlan, decision: Decision) -> str:
    """STUB: returns a fake hash, sends nothing. Real version verifies the approval token,
    signs and sends (Person 1, task 6)."""
    return "0x" + "00" * 32


def balances() -> dict:
    """{'ETH': '...', 'TUSD': '...'} for the wallet in .env."""
    return chain.balances()


def approvals() -> list:
    """[{'token', 'spender', 'allowance'}] with non-zero allowances."""
    return chain.approvals()
