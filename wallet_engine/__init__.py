"""Wallet engine facade (Person 1 owns this folder).

All five functions are REAL now:
  plan()      build the exact transaction            (chain.py / erc20.py)
  simulate()  dry-run it, send nothing               (simulate.py)
  execute()   sign + send, only with a valid token   (execute.py)
  balances(), approvals()  read the wallet           (chain.py)
SIGNATURES must not change (tests/test_contract.py checks them).

Token binding: the approval token must be tied to what is really signed. Use
`wallet_engine.binding.token_binding(plan)` to get {action, token, to, amount}.
"""
from shared.types import ActionRequest, Decision, SimResult, TxPlan

from . import chain, erc20
from .execute import ExecutionFailed, ExecutionPending, ExecutionRefused
from .execute import run as _execute
from .simulate import run as _simulate


def plan(req: ActionRequest) -> TxPlan:
    """Build the exact transaction for an ActionRequest. Nothing is signed or sent."""
    return erc20.plan(chain.get_web3(), req, chain.wallet_address())


def simulate(plan: TxPlan) -> SimResult:
    """Dry-run the transaction (eth_call + estimate_gas). Never raises: failures come back as ok=False."""
    return _simulate(plan)


def execute(plan: TxPlan, decision: Decision) -> str:
    """Sign and send. Raises ExecutionRefused (nothing sent) unless the decision is 'allow' with a
    token that matches exactly this transaction. Returns the transaction hash."""
    return _execute(plan, decision)


def balances() -> dict:
    """{'ETH': '...', 'TUSD': '...'} for the wallet in .env."""
    return chain.balances()


def approvals() -> list:
    """[{'token', 'spender', 'allowance'}] with non-zero allowances."""
    return chain.approvals()
