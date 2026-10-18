"""Shared test setup. EVERY test gets its own temporary copies of the files the firewall writes
(audit log, spending record, kill-switch flag) and a clean firewall memory, so tests never touch the
real logs/ folder and never affect each other."""
import pytest


@pytest.fixture(autouse=True)
def _isolated_files(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SPEND_LEDGER_PATH", str(tmp_path / "spend_ledger.jsonl"))
    monkeypatch.setenv("KILL_SWITCH_PATH", str(tmp_path / "kill_switch.flag"))
    monkeypatch.setenv("USED_TOKENS_PATH", str(tmp_path / "used_tokens.jsonl"))     # spent approval tokens
    monkeypatch.setenv("VELOCITY_PATH", str(tmp_path / "velocity.jsonl"))            # recent action timestamps
    monkeypatch.setenv("APPROVAL_SECRET", "test-only-secret-0123456789abcdef")


@pytest.fixture(autouse=True)
def _no_real_sepolia(monkeypatch):
    """NO test may ever reach the public testnet. The developer's .env holds a funded Sepolia key and a working RPC URL
    (python-dotenv loads it when a module is imported), so a test that switches ACTIVE_NETWORK to sepolia and then
    runs code that sends would send REAL transactions. Both settings are replaced by unusable values for every test
    (set, not deleted: load_dotenv would put a deleted variable back). Tests that need a Sepolia-looking setup set their
    own fake values afterwards."""
    monkeypatch.setenv("RPC_URL_SEPOLIA", "http://127.0.0.1:9")                 # nothing listens on the discard port
    monkeypatch.setenv("SEPOLIA_PRIVATE_KEY", "0x" + "00" * 32)                  # not a valid secp256k1 key: cannot sign


@pytest.fixture(autouse=True)
def _operator_token(monkeypatch):
    """The API's operator key (Confirm, kill switch OFF). Tests send it with tests.operator_key.operator_headers()."""
    from tests.operator_key import OPERATOR_TOKEN
    monkeypatch.setenv("OPERATOR_TOKEN", OPERATOR_TOKEN)


@pytest.fixture(autouse=True)
def _clean_firewall(_isolated_files):
    # runs BEFORE each test (each test also has brand-new temporary files, so nothing needs cleaning afterwards)
    from firewall import policy, state, tokens
    state.reset()
    tokens.reset()
    policy.reset()