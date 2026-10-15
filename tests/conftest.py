"""Shared test setup: keep the real audit log (logs/audit.jsonl) out of the test runs and start every
test with a clean firewall (no remembered spending, tokens, open questions, kill switch)."""
import pytest


@pytest.fixture(autouse=True)
def _isolated_audit_log(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))


@pytest.fixture(autouse=True)
def _clean_firewall():
    from firewall import policy, state, tokens
    state.reset()
    tokens.reset()
    policy.reset()
    yield
    state.reset()
    tokens.reset()
    policy.reset()