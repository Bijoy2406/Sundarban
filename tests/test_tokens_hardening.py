"""Extra protections in firewall/tokens.py: one use only, and the kill switch cancels tokens."""
import pytest

from firewall import state, tokens

TOKEN = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
AMOUNT = "10000000000000000000"


@pytest.fixture(autouse=True)
def secret(monkeypatch):
    monkeypatch.setenv("APPROVAL_SECRET", "unit-test-secret-0123456789abcdef")


def _issue(request_id="r1"):
    return tokens.issue_token(request_id, "transfer", TOKEN, ALICE, AMOUNT)


def _verify(t, request_id="r1"):
    return tokens.verify_token(t, request_id, "transfer", TOKEN, ALICE, AMOUNT)


def test_a_token_works_once_and_only_once():
    t = _issue()
    assert _verify(t) is True
    assert _verify(t) is False          # replay refused


def test_a_failed_check_does_not_use_up_the_token():
    t = _issue()
    assert tokens.verify_token(t, "r1", "transfer", TOKEN, ALICE, "1") is False   # wrong amount
    assert _verify(t) is True                                                      # still usable for the right tx


def test_different_requests_get_independent_tokens():
    a, b = _issue("r1"), _issue("r2")
    assert _verify(a, "r1") is True
    assert _verify(b, "r2") is True


def test_kill_switch_cancels_a_token_that_was_already_issued():
    t = _issue()
    state.set_kill_switch(True)
    assert _verify(t) is False
    state.set_kill_switch(False)
    assert _verify(t) is True           # it was never used up while the switch was on


def test_used_tokens_are_forgotten_after_they_expire(monkeypatch):
    t = tokens.issue_token("r1", "transfer", TOKEN, ALICE, AMOUNT, ttl_seconds=10)
    assert _verify(t) is True
    real = tokens.time.time
    monkeypatch.setattr(tokens.time, "time", lambda: real() + 11)
    _verify(_issue("other"), "other")  # any later check cleans out the expired entry
    assert t not in tokens._USED