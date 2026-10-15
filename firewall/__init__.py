"""Firewall facade (Person 2 owns this folder).

evaluate() and confirm() are REAL now: they call policy.py (rules), which uses state.py (limits, spend,
kill switch), provenance.py (origin check), tokens.py (approval tokens) and audit.py (hash-chained log).
The function SIGNATURES must not change (tests/test_contract.py checks them).
"""
from . import audit, policy, provenance, state, tokens  # noqa: F401  (re-exported on purpose)

evaluate = policy.evaluate
confirm = policy.confirm