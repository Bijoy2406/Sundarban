"""Shared test setup. EVERY test gets its own temporary copies of the files the firewall writes
(audit log, spending record, kill-switch flag) and a clean firewall memory, so tests never touch the
real logs/ folder and never affect each other."""
import pytest


@pytest.fixture(autouse=True)
def _isolated_files(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SPEND_LEDGER_PATH", str(tmp_path / "spend_ledger.jsonl"))
    monkeypatch.setenv("KILL_SWITCH_PATH", str(tmp_path / "kill_switch.flag"))
    monkeypatch.setenv("APPROVAL_SECRET", "test-only-secret-0123456789abcdef")


@pytest.fixture(autouse=True)
def _clean_firewall(_isolated_files):
    # runs BEFORE each test (each test also has brand-new temporary files, so nothing needs cleaning afterwards)
    from firewall import policy, state, tokens
    state.reset()
    tokens.reset()
    policy.reset()