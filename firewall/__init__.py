"""Firewall facade (Person 2 owns this folder).

STUB: every function below returns a fake, clearly-labelled answer so Person 1 and
Person 3 can import and run against it. Person 2 replaces the bodies with the real
rules (policy.py), approval tokens (tokens.py) and audit log (audit.py).
The function SIGNATURES must not change.
"""
from typing import Optional

from shared.types import ActionRequest, Decision, SimResult, TxPlan

from . import audit, state, tokens  # noqa: F401  (re-exported on purpose)


def evaluate(req: ActionRequest, plan: Optional[TxPlan] = None, sim: Optional[SimResult] = None) -> Decision:
    """STUB: always 'allow'. NOT a real decision. Replace with policy.evaluate."""
    return Decision(
        request_id=req.request_id,
        decision="allow",
        rule_ids=["STUB"],
        reasons=["STUB firewall: no rules are enforced yet"],
        approval_token=tokens.STUB_TOKEN,
    )


def confirm(req: ActionRequest, plan: Optional[TxPlan] = None) -> Decision:
    """STUB: pretend the human confirmed. Replace with the real token issuing."""
    return Decision(
        request_id=req.request_id,
        decision="allow",
        rule_ids=["STUB"],
        reasons=["STUB firewall: confirmed without checks"],
        approval_token=tokens.STUB_TOKEN,
    )
