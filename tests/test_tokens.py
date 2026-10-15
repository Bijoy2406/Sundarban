"""Tests for firewall/tokens.py (issue #16): valid passes; wrong amount / recipient / expired / tampered all fail."""
import pytest

from firewall import tokens

TOKEN = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
BOB = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
AMOUNT = "10000000000000000000"


@pytest.fixture(autouse=True)
def secret(monkeypatch):
    monkeypatch.setenv("APPROVAL_SECRET", "unit-test-secret-0123456789abcdef")


def _issue(**over):
    args = dict(request_id="r1", action="transfer", token=TOKEN, to=ALICE, amount=AMOUNT)
    args.update(over)
    return tokens.issue_token(**args)


def _verify(t, **over):
    args = dict(request_id="r1", action="transfer", token_addr=TOKEN, to=ALICE, amount=AMOUNT)
    args.update(over)
    return tokens.verify_token(t, **args)


def test_valid_token_passes():
    assert _verify(_issue()) is True


def test_address_case_does_not_matter():
    assert _verify(_issue(), token_addr=TOKEN.lower(), to=ALICE.lower()) is True


def test_wrong_amount_fails():
    assert _verify(_issue(), amount="10000000000000000001") is False


def test_wrong_recipient_fails():
    assert _verify(_issue(), to=BOB) is False


def test_wrong_action_fails():
    assert _verify(_issue(), action="approve") is False


def test_wrong_token_contract_fails():
    assert _verify(_issue(), token_addr=BOB) is False


def test_wrong_request_id_fails():
    assert _verify(_issue(), request_id="r2") is False


def test_expired_token_fails(monkeypatch):
    t = _issue(ttl_seconds=60)
    real_time = tokens.time.time
    monkeypatch.setattr(tokens.time, "time", lambda: real_time() + 61)
    assert _verify(t) is False


def test_already_expired_on_issue_fails():
    assert _verify(_issue(ttl_seconds=-1)) is False


def test_tampered_mac_fails():
    expiry, mac = _issue().split(".")
    flipped = ("0" if mac[0] != "0" else "1") + mac[1:]
    assert _verify(f"{expiry}.{flipped}") is False


def test_tampered_expiry_fails():
    expiry, mac = _issue(ttl_seconds=60).split(".")
    assert _verify(f"{int(expiry) + 100000}.{mac}") is False


def test_token_signed_with_another_secret_fails(monkeypatch):
    t = _issue()
    monkeypatch.setenv("APPROVAL_SECRET", "a-completely-different-secret-value")
    assert _verify(t) is False


@pytest.mark.parametrize("junk", ["", "garbage", ".", "123.", ".abc", "abc.def", None, 12345, tokens.STUB_TOKEN])
def test_junk_tokens_fail_without_raising(junk):
    assert _verify(junk) is False


def test_missing_secret_cannot_issue_and_cannot_verify(monkeypatch):
    t = _issue()
    monkeypatch.delenv("APPROVAL_SECRET")
    with pytest.raises(RuntimeError):
        _issue()
    assert _verify(t) is False