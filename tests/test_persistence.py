"""State that must survive a restart: spent approval tokens (firewall/tokens.py) and the velocity window
(firewall/state.py). Both live in small files (USED_TOKENS_PATH, VELOCITY_PATH) that conftest.py points into the
per-test temp folder, so no test ever touches the real logs/ folder.

Restart is simulated in two ways: clearing the in-memory structures while the file stays, and a REAL second process."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from firewall import policy, state, tokens
from shared.types import ActionRequest, SimResult, TxPlan

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
AMOUNT = "10000000000000000000"
SECRET = "unit-test-secret-0123456789abcdef"


@pytest.fixture(autouse=True)
def secret(monkeypatch):
    monkeypatch.setenv("APPROVAL_SECRET", SECRET)


def _issue(rid="r1"):
    return tokens.issue_token(rid, "transfer", TOKEN, ALICE, AMOUNT)


def _verify(t, rid="r1"):
    return tokens.verify_token(t, rid, "transfer", TOKEN, ALICE, AMOUNT)


def _restart():
    """What a restart does to the process: all memory is gone, the files stay."""
    tokens._USED.clear()
    state._ACTIONS.clear()


# ====================================================================== used tokens

def test_a_spent_token_is_refused_after_a_restart():
    t = _issue()
    assert _verify(t) is True
    _restart()
    assert _verify(t) is False


def test_a_spent_token_is_refused_by_a_brand_new_process(tmp_path):
    env = {**os.environ, "APPROVAL_SECRET": SECRET, "USED_TOKENS_PATH": str(tmp_path / "used.jsonl"),
           "SPEND_LEDGER_PATH": str(tmp_path / "l.jsonl"), "KILL_SWITCH_PATH": str(tmp_path / "k.flag"),
           "AUDIT_LOG_PATH": str(tmp_path / "a.jsonl")}
    first = ("from firewall import tokens\n"
             f"t = tokens.issue_token('r9', 'transfer', '{TOKEN}', '{ALICE}', '{AMOUNT}')\n"
             f"assert tokens.verify_token(t, 'r9', 'transfer', '{TOKEN}', '{ALICE}', '{AMOUNT}') is True\nprint(t)")
    token = subprocess.run([sys.executable, "-c", first], cwd=ROOT, env=env, capture_output=True, text=True, check=True).stdout.strip()
    second = ("from firewall import tokens\n"
              f"print(tokens.verify_token('{token}', 'r9', 'transfer', '{TOKEN}', '{ALICE}', '{AMOUNT}'))")
    out = subprocess.run([sys.executable, "-c", second], cwd=ROOT, env=env, capture_output=True, text=True, check=True).stdout.strip()
    assert out == "False"


def test_the_file_keeps_only_the_signature_and_the_expiry():
    t = _issue()
    _verify(t)
    expiry, _, mac = t.partition(".")
    lines = tokens._used_path().read_text().splitlines()
    assert [json.loads(line) for line in lines] == [{"sig": mac, "exp": int(expiry)}]
    assert t not in tokens._used_path().read_text()


def test_the_default_location_is_the_logs_folder_and_the_variable_overrides_it(monkeypatch, tmp_path):
    monkeypatch.delenv("USED_TOKENS_PATH")
    assert tokens._used_path() == ROOT / "logs" / "used_tokens.jsonl"
    monkeypatch.setenv("USED_TOKENS_PATH", str(tmp_path / "x.jsonl"))
    assert tokens._used_path() == tmp_path / "x.jsonl"


def test_the_write_is_flushed_to_disk_before_true_is_returned(monkeypatch):
    synced = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real(fd))[1])
    assert _verify(_issue()) is True
    assert synced, "the used-token record must be fsync'd before the token counts as accepted"


def test_expired_entries_are_dropped_when_a_new_one_is_written():
    path = tokens._used_path()
    path.write_text(json.dumps({"sig": "a" * 64, "exp": int(time.time()) - 500}) + "\n"
                    + json.dumps({"sig": "b" * 64, "exp": int(time.time()) + 500}) + "\n")
    assert _verify(_issue()) is True
    sigs = [json.loads(line)["sig"] for line in path.read_text().splitlines()]
    assert "a" * 64 not in sigs and "b" * 64 in sigs and len(sigs) == 2


@pytest.mark.parametrize("content", [b"not json\n", b'{"sig": "x"}\n', b'{"sig": 5, "exp": "soon"}\n',
                                     b'{"sig":"' + b"a" * 64 + b'","exp":9999999999}', b"\xff\xfe\n"])
def test_an_unreadable_used_token_file_fails_closed(content):
    tokens._used_path().write_bytes(content)
    assert _verify(_issue()) is False


def test_a_used_token_path_that_cannot_be_read_fails_closed(monkeypatch, tmp_path):
    directory = tmp_path / "a_directory"
    directory.mkdir()
    monkeypatch.setenv("USED_TOKENS_PATH", str(directory))
    assert _verify(_issue()) is False


def test_a_failed_write_does_not_accept_the_token(monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("disk full")
    t = _issue()
    with monkeypatch.context() as scoped:
        scoped.setattr(state, "_append_durable", broken)
        assert _verify(t) is False
    assert _verify(t) is True                      # nothing was recorded, so the token was not burnt either


def test_reset_clears_the_file_too():
    _verify(_issue())
    assert tokens._used_path().exists()
    tokens.reset()
    assert not tokens._used_path().exists() and tokens._USED == {}


def test_reset_never_touches_the_real_logs_folder(monkeypatch):
    monkeypatch.delenv("USED_TOKENS_PATH")
    before = (ROOT / "logs" / "used_tokens.jsonl").exists()
    tokens.reset()
    assert (ROOT / "logs" / "used_tokens.jsonl").exists() == before


# ====================================================================== velocity

def test_the_velocity_count_survives_a_restart():
    for _ in range(3):
        state.record_action()
    assert state.actions_in_window() == 3
    _restart()
    assert state.actions_in_window() == 3


def test_the_velocity_count_survives_a_brand_new_process(tmp_path):
    env = {**os.environ, "VELOCITY_PATH": str(tmp_path / "v.jsonl"), "SPEND_LEDGER_PATH": str(tmp_path / "l.jsonl"),
           "KILL_SWITCH_PATH": str(tmp_path / "k.flag"), "APPROVAL_SECRET": SECRET}
    run = lambda code: subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, check=True).stdout.strip()
    run("from firewall import state\nstate.record_action(); state.record_action(); state.record_action()")
    assert run("from firewall import state\nprint(state.actions_in_window())") == "3"


def test_the_window_is_live_old_actions_fall_out(monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(state, "_clock", lambda: now[0])
    state.record_action()
    now[0] += 400
    state.record_action()
    _restart()
    assert state.actions_in_window(600) == 2
    now[0] += 300                                   # the first action is now 700 s old
    assert state.actions_in_window(600) == 1


def test_the_default_velocity_location_and_override(monkeypatch, tmp_path):
    monkeypatch.delenv("VELOCITY_PATH")
    assert state._velocity_path() == ROOT / "logs" / "velocity.jsonl"
    monkeypatch.setenv("VELOCITY_PATH", str(tmp_path / "v.jsonl"))
    assert state._velocity_path() == tmp_path / "v.jsonl"


def test_actions_older_than_a_day_are_dropped_when_writing(monkeypatch):
    now = [5_000_000.0]
    monkeypatch.setattr(state, "_clock", lambda: now[0])
    state.record_action()
    now[0] += state.DAY_SECONDS + 10
    state.record_action()
    assert len(state._velocity_path().read_text().splitlines()) == 1


def test_the_velocity_write_is_flushed_to_disk(monkeypatch):
    synced = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real(fd))[1])
    state.record_action()
    assert synced


@pytest.mark.parametrize("content", [b"garbage\n", b'{"ts": "yesterday"}\n', b'{"ts": 1.0}', b"\xff\n"])
def test_an_unreadable_velocity_file_counts_as_at_the_limit(content):
    state._velocity_path().write_bytes(content)
    limit = state.load_rules()["velocity_max_actions"]
    assert state.actions_in_window() == limit


def test_recording_with_an_unreadable_velocity_file_does_not_crash_and_changes_nothing():
    state._velocity_path().write_bytes(b"garbage\n")
    state.record_action()
    assert state._velocity_path().read_bytes() == b"garbage\n"        # the evidence is not overwritten


def _plan(amount_tokens=10):
    data = "0xa9059cbb" + ALICE[2:].lower().rjust(64, "0") + hex(amount_tokens * 10**18)[2:].rjust(64, "0")
    return TxPlan(31337, "0x" + "1" * 40, TOKEN, 0, data, 60000, "transfer(address,uint256)", {}, "x")


@pytest.fixture
def rules(monkeypatch, tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text('auto_limit: "50"\nmax_tx: "500"\ndaily_cap: "1000"\nvelocity: {max_actions: 5, window_seconds: 600}\n'
                    f'trusted_origins: [user_chat]\nchain_id: 31337\nallowlist: ["{ALICE}"]\n')
    monkeypatch.setenv("RULES_PATH", str(path))
    monkeypatch.setenv("TOKEN_ADDRESS", TOKEN)


def _evaluate(rid):
    req = ActionRequest(rid, "transfer", TOKEN, ALICE, "10", False, "user_chat")
    return policy.evaluate(req, _plan(), SimResult(True, None, "10", None))


def test_a_restart_does_not_hand_out_a_fresh_velocity_budget(rules):
    for i in range(5):
        assert _evaluate(f"a{i}").decision == "allow"
    _restart()
    sixth = _evaluate("a5")
    assert sixth.decision == "ask" and sixth.rule_ids == ["VEL-01"]


def test_an_unreadable_velocity_file_makes_the_answer_ask_never_allow(rules):
    state._velocity_path().write_bytes(b"garbage\n")
    answer = _evaluate("b1")
    assert answer.decision == "ask" and "VEL-01" in answer.rule_ids and answer.approval_token is None


# ====================================================================== isolation

def test_conftest_points_both_files_into_the_test_temp_folder(tmp_path):
    assert tokens._used_path().parent == tmp_path and state._velocity_path().parent == tmp_path


def test_state_reset_clears_the_velocity_file_and_needs_the_path_variable(monkeypatch):
    state.record_action()
    state.reset()
    assert not state._velocity_path().exists() and state.actions_in_window() == 0
    monkeypatch.delenv("VELOCITY_PATH")
    with pytest.raises(RuntimeError, match="VELOCITY_PATH"):
        state.reset()


def test_a_normal_test_run_creates_nothing_in_the_real_logs_folder():
    real = [ROOT / "logs" / "used_tokens.jsonl", ROOT / "logs" / "velocity.jsonl"]
    before = [(p.exists(), p.stat().st_mtime_ns if p.exists() else 0) for p in real]
    _verify(_issue())
    state.record_action()
    tokens.reset()
    state.reset()
    after = [(p.exists(), p.stat().st_mtime_ns if p.exists() else 0) for p in real]
    assert before == after


def test_the_red_team_runner_isolates_both_files_and_leaves_the_real_logs_alone(tmp_path):
    from firewall.redteam import run
    real = [ROOT / "logs" / "used_tokens.jsonl", ROOT / "logs" / "velocity.jsonl"]
    before = [(p.exists(), p.stat().st_mtime_ns if p.exists() else 0) for p in real]
    seen = {}
    with run.isolated_firewall(tmp_path):
        run._begin_case(tmp_path / "case", state.load_rules(), 31337, {"recent_actions": 2})
        seen["used"], seen["velocity"] = tokens._used_path(), state._velocity_path()
        seen["count"] = state.actions_in_window()
    assert seen["used"].parent == tmp_path / "case" and seen["velocity"].parent == tmp_path / "case"
    assert seen["count"] == 2
    report = run.run_all(run.load_cases(only=["atk-031", "ben-001"]), tmp_path / "full", agents=False)
    assert run.all_passed(report)
    assert before == [(p.exists(), p.stat().st_mtime_ns if p.exists() else 0) for p in real]
