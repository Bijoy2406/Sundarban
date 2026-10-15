"""Hash-chained audit log (issue #17): firewall/audit.py. Everything runs offline."""
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from firewall import audit
from firewall.audit import GENESIS, AuditCorruptError

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def path(tmp_path, monkeypatch):
    p = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AUDIT_LOG_PATH", str(p))
    return p


def _fill(n=5):
    for i in range(n):
        audit.log({"event": "TEST", "i": i})


def _lines(p: Path) -> list[str]:
    return p.read_text().split("\n")[:-1]


def _write(p: Path, lines: list[str]) -> None:
    p.write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------- writing

def test_log_creates_file_and_chain_links(path):
    _fill(3)
    entries = [json.loads(line) for line in _lines(path)]
    assert [e["seq"] for e in entries] == [0, 1, 2]
    assert entries[0]["prev_hash"] == GENESIS
    assert entries[1]["prev_hash"] == entries[0]["hash"]
    assert entries[2]["prev_hash"] == entries[1]["hash"]
    assert set(entries[0]) == {"seq", "ts", "event", "prev_hash", "hash"}
    assert entries[0]["ts"].endswith("Z") and len(entries[0]["hash"]) == 64


def test_intact_log_verifies(path):
    _fill(10)
    assert audit.verify() is True
    assert audit.verify(path) is True
    result = audit.check()
    assert (result.ok, result.entries) == (True, 10)
    assert result.head == json.loads(_lines(path)[-1])["hash"]


def test_empty_or_missing_log_is_valid(path):
    assert audit.verify() is True                       # nothing written yet
    path.write_text("")
    assert audit.verify() is True
    assert audit.head() is None


def test_log_continues_an_existing_chain(path):
    _fill(2)
    audit.log({"event": "LATER"})
    assert audit.check().entries == 3 and audit.verify()


def test_rejects_non_dict_events(path):
    for bad in ("text", 5, None, ["a"]):
        with pytest.raises(TypeError):
            audit.log(bad)
    assert not path.exists()


def test_odd_values_are_stored_safely(path):
    from decimal import Decimal
    audit.log({"event": "ODD", "amount": Decimal("1.5"), "tuple": (1, 2), "unicode": "ক্যাশ ✓", "nested": {"a": [1, {"b": 2}]}})
    entry = audit.tail(1)[0]
    assert entry["event"]["amount"] == "1.5" and entry["event"]["tuple"] == [1, 2]
    assert entry["event"]["unicode"] == "ক্যাশ ✓"
    assert audit.verify()


def test_nan_is_rejected(path):
    with pytest.raises(ValueError):
        audit.log({"event": "BAD", "x": float("nan")})
    assert not path.exists() or audit.verify()


def test_secrets_are_redacted_before_writing(path):
    audit.log({"event": "SECRETS", "private_key": "0xabc", "approval_token": "123.deadbeef",
               "APPROVAL_SECRET": "s3cret", "nested": {"api_key": "k", "keep": "visible"},
               "token": "0x5FbDB2315678afecb367f032d93F642f64180aa3"})
    text = path.read_text()
    for leaked in ("0xabc", "deadbeef", "s3cret", '"k"'):
        assert leaked not in text
    event = audit.tail(1)[0]["event"]
    assert event["private_key"] == event["approval_token"] == event["APPROVAL_SECRET"] == "[REDACTED]"
    assert event["nested"] == {"api_key": "[REDACTED]", "keep": "visible"}
    assert event["token"].startswith("0x5Fb")                # a token ADDRESS is not a secret
    assert audit.verify()


# ---------------------------------------------------------------- tamper detection

def test_edited_event_is_detected(path):
    _fill(5)
    lines = _lines(path)
    lines[2] = lines[2].replace('"i":2', '"i":999')
    _write(path, lines)
    result = audit.check()
    assert result.ok is False and result.line == 3 and "modified" in result.reason


def test_edited_hash_is_detected(path):
    _fill(5)
    lines = _lines(path)
    entry = json.loads(lines[1])
    entry["hash"] = "f" * 64
    lines[1] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    _write(path, lines)
    assert audit.verify() is False


def test_deleted_middle_line_is_detected(path):
    _fill(5)
    lines = _lines(path)
    del lines[2]
    _write(path, lines)
    assert audit.verify() is False


def test_deleted_first_line_is_detected(path):
    _fill(4)
    _write(path, _lines(path)[1:])
    assert audit.verify() is False


def test_inserted_line_is_detected(path):
    _fill(4)
    lines = _lines(path)
    forged = {"seq": 2, "ts": "2026-01-01T00:00:00.000000Z", "event": {"event": "FORGED"},
              "prev_hash": json.loads(lines[1])["hash"], "hash": "0" * 64}
    lines.insert(2, json.dumps(forged, sort_keys=True, separators=(",", ":")))
    _write(path, lines)
    assert audit.verify() is False


def _resign(entry: dict) -> str:
    """What a forger who knows the format would do: recompute this entry's own hash."""
    entry["hash"] = audit._entry_hash(entry["seq"], entry["ts"], entry["event"], entry["prev_hash"])
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def test_a_resigned_entry_that_does_not_link_is_detected(path):
    """Own hash and numbering are valid; ONLY the link to the previous entry is wrong."""
    _fill(4)
    lines = _lines(path)
    forged = json.loads(lines[2])
    forged["prev_hash"] = GENESIS
    lines[2] = _resign(forged)
    _write(path, lines)
    result = audit.check()
    assert result.ok is False and result.line == 3 and "link" in result.reason


def test_deleting_a_line_and_resigning_the_next_still_leaves_a_numbering_gap(path):
    """Links and hashes are all valid again; ONLY the entry numbers give it away."""
    _fill(4)
    lines = _lines(path)
    del lines[1]
    for i in range(1, len(lines)):                           # re-link and re-sign everything after the gap
        e = json.loads(lines[i])
        e["prev_hash"] = json.loads(lines[i - 1])["hash"]
        lines[i] = _resign(e)
    _write(path, lines)
    result = audit.check()
    assert result.ok is False and "expected" in result.reason


def test_reordered_lines_are_detected(path):
    _fill(4)
    lines = _lines(path)
    lines[1], lines[2] = lines[2], lines[1]
    _write(path, lines)
    assert audit.verify() is False


def test_duplicated_line_is_detected(path):
    _fill(3)
    lines = _lines(path)
    lines.append(lines[-1])
    _write(path, lines)
    assert audit.verify() is False


def test_garbage_blank_and_partial_lines_are_detected(path):
    _fill(3)
    good = path.read_text()
    for bad in (good + "not json\n", good + "\n", good + '{"seq":3', good + "[]\n", good + '{"seq":3}\n'):
        path.write_text(bad)
        assert audit.verify() is False, repr(bad[-20:])


def test_truncation_needs_an_expected_head(path):
    _fill(5)
    anchored = audit.head()
    assert anchored["seq"] == 4
    _write(path, _lines(path)[:3])                       # silently drop the last two entries
    assert audit.verify() is True                        # a shorter chain is still a valid chain...
    assert audit.verify(expected_head=anchored["hash"]) is False    # ...unless you kept the head
    assert "head hash differs" in audit.check(expected_head=anchored["hash"]).reason


def test_expected_head_matches_when_untouched(path):
    _fill(3)
    assert audit.verify(expected_head=audit.head()["hash"]) is True


def test_missing_file_with_expected_head_fails(path):
    assert audit.verify(expected_head="a" * 64) is False


# ---------------------------------------------------------------- refusing to extend a broken log

def test_log_refuses_to_extend_a_partial_last_line(path):
    _fill(2)
    with open(path, "ab") as f:
        f.write(b'{"seq":2,"ts"')                        # a crashed half-written entry
    with pytest.raises(AuditCorruptError):
        audit.log({"event": "NEXT"})
    assert audit.verify() is False


def test_log_refuses_to_extend_after_the_last_entry_was_edited(path):
    _fill(2)
    lines = _lines(path)
    lines[-1] = lines[-1].replace('"i":1', '"i":7')
    _write(path, lines)
    with pytest.raises(AuditCorruptError):
        audit.log({"event": "NEXT"})


# ---------------------------------------------------------------- concurrency

def test_threads_can_write_the_same_log(path):
    def work(k):
        for i in range(20):
            audit.log({"event": "T", "thread": k, "i": i})
    threads = [threading.Thread(target=work, args=(k,)) for k in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    result = audit.check()
    assert (result.ok, result.entries) == (True, 120)


def test_processes_can_write_the_same_log(path):
    code = ("import os; from firewall import audit\n"
            "for i in range(25): audit.log({'event': 'P', 'pid': os.getpid(), 'i': i})\n")
    procs = [subprocess.Popen([sys.executable, "-c", code], cwd=ROOT) for _ in range(4)]
    assert [p.wait(timeout=60) for p in procs] == [0, 0, 0, 0]
    result = audit.check()
    assert (result.ok, result.entries) == (True, 100)
    assert [e["seq"] for e in audit.tail(1000)] == list(range(100))


# ---------------------------------------------------------------- viewer helpers and CLI

def test_tail_returns_the_newest_entries(path):
    _fill(8)
    assert [e["event"]["i"] for e in audit.tail(3)] == [5, 6, 7]
    assert audit.tail(0) == []
    assert len(audit.tail(100)) == 8


def test_cli_verify_ok_and_failed(path):
    _fill(3)
    ok = subprocess.run([sys.executable, "scripts/verify_audit.py", str(path)], cwd=ROOT,
                        capture_output=True, text=True)
    assert ok.returncode == 0 and ok.stdout.startswith("OK: 3 entries")
    lines = _lines(path)
    lines[1] = lines[1].replace('"i":1', '"i":5')
    _write(path, lines)
    bad = subprocess.run([sys.executable, "scripts/verify_audit.py", str(path)], cwd=ROOT,
                         capture_output=True, text=True)
    assert bad.returncode == 1 and bad.stdout.startswith("FAILED") and "line 2" in bad.stdout


# ---------------------------------------------------------------- integration with the wallet engine

def test_execute_refusals_are_written_to_the_audit_log(path):
    import wallet_engine
    from shared.types import Decision, TxPlan
    from wallet_engine.execute import ExecutionRefused
    plan = TxPlan(chain_id=31337, from_addr="0x" + "11" * 20, to="0x" + "22" * 20, value=0, data="0x",
                  gas=60_000, function="", args={}, summary="")
    with pytest.raises(ExecutionRefused):
        wallet_engine.execute(plan, Decision(request_id="req-audit", decision="deny", approval_token="x"))
    entry = audit.tail(1)[0]["event"]
    assert entry["event"] == "EXECUTE_REFUSED" and entry["request_id"] == "req-audit"
    assert audit.verify()


def test_the_default_location_is_the_git_ignored_logs_folder(monkeypatch):
    monkeypatch.delenv("AUDIT_LOG_PATH", raising=False)
    assert audit.default_path() == ROOT / "logs" / "audit.jsonl"
