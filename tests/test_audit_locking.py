"""Cross-process locking of the audit log on every platform (issue #17).

Person 3 runs Windows, where `fcntl` does not exist. Before this fix several processes could append at the
same time and corrupt the hash chain (`AuditCorruptError: the audit log ends with a blank line`).

These tests run on Linux but force the other code paths:
  * AUDIT_LOCK_MODE=portable   the exclusive-create lock file (used when no OS lock exists)
  * AUDIT_LOCK_MODE=msvcrt     the real Windows code path, with a stand-in `msvcrt` module built on POSIX locks
The writers are separate processes, so the locks are really exercised.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from firewall import audit

ROOT = Path(__file__).resolve().parents[1]
WRITERS, WRITES_EACH = 4, 200

PORTABLE_WRITER = (
    "import os\n"
    "from firewall import audit\n"
    "for i in range({n}): audit.log({{'event': 'P', 'pid': os.getpid(), 'i': i}})\n"
)

# A stand-in for Windows' msvcrt that uses POSIX record locks underneath, so the REAL _msvcrt_lock code runs.
FAKE_MSVCRT_WRITER = (
    "import fcntl, os, types\n"
    "from firewall import audit\n"
    "def locking(fd, mode, nbytes):\n"
    "    if mode == 2:   # LK_NBLCK: lock without waiting, raise OSError if somebody else holds it\n"
    "        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, nbytes, 0, 0)\n"
    "    else:           # LK_UNLCK\n"
    "        fcntl.lockf(fd, fcntl.LOCK_UN, nbytes, 0, 0)\n"
    "audit.msvcrt = types.SimpleNamespace(LK_NBLCK=2, LK_UNLCK=0, locking=locking)\n"
    "audit.fcntl = None\n"
    "for i in range({n}): audit.log({{'event': 'W', 'pid': os.getpid(), 'i': i}})\n"
)


def _run_writers(code: str, mode: str):
    env = dict(os.environ, AUDIT_LOCK_MODE=mode)
    procs = [subprocess.Popen([sys.executable, "-c", code.format(n=WRITES_EACH)], cwd=ROOT, env=env,
                              stderr=subprocess.PIPE) for _ in range(WRITERS)]
    outcomes = []
    for p in procs:
        _, err = p.communicate(timeout=180)
        outcomes.append((p.returncode, err.decode()[-300:]))
    return outcomes


def _assert_perfect_log():
    total = WRITERS * WRITES_EACH
    result = audit.check()
    assert (result.ok, result.entries) == (True, total), result
    assert [e["seq"] for e in audit.tail(total + 10)] == list(range(total))


def test_portable_lock_keeps_the_chain_intact_across_processes():
    outcomes = _run_writers(PORTABLE_WRITER, "portable")
    assert [code for code, _ in outcomes] == [0] * WRITERS, outcomes
    _assert_perfect_log()
    assert not audit._portable_lock_path(audit.default_path()).exists()   # released at the end


def test_windows_code_path_keeps_the_chain_intact_across_processes():
    outcomes = _run_writers(FAKE_MSVCRT_WRITER, "msvcrt")
    assert [code for code, _ in outcomes] == [0] * WRITERS, outcomes
    _assert_perfect_log()


def test_lock_mode_selection(monkeypatch):
    monkeypatch.delenv("AUDIT_LOCK_MODE", raising=False)
    fake = object()
    monkeypatch.setattr(audit, "fcntl", fake)
    assert audit._lock_mode() == "fcntl"
    monkeypatch.setattr(audit, "fcntl", None)
    monkeypatch.setattr(audit, "msvcrt", fake)
    assert audit._lock_mode() == "msvcrt"                               # Windows
    monkeypatch.setattr(audit, "msvcrt", None)
    assert audit._lock_mode() == "portable"                             # neither exists


def test_a_forced_mode_that_is_not_available_falls_back_to_portable(monkeypatch):
    monkeypatch.setattr(audit, "fcntl", None)
    monkeypatch.setattr(audit, "msvcrt", None)
    for forced in ("fcntl", "msvcrt", "portable", "nonsense"):
        monkeypatch.setenv("AUDIT_LOCK_MODE", forced)
        expected = "portable" if forced != "nonsense" else "portable"
        assert audit._lock_mode() == expected


def test_a_filesystem_without_flock_does_not_silently_lose_the_lock(monkeypatch):
    """flock failing (some FUSE / network drives) used to mean 'carry on with no lock'. Now: portable lock."""
    class NoFlock:
        LOCK_EX, LOCK_UN = 2, 8

        @staticmethod
        def flock(fd, op):
            raise OSError("flock is not supported on this file system")
    monkeypatch.setenv("AUDIT_LOCK_MODE", "fcntl")
    monkeypatch.setattr(audit, "fcntl", NoFlock)
    seen = []
    real = audit._portable_lock

    def spy(path):
        seen.append(path)
        return real(path)
    monkeypatch.setattr(audit, "_portable_lock", spy)
    audit.log({"event": "a"})
    audit.log({"event": "b"})
    assert len(seen) == 2                                               # the fallback really ran
    assert audit.check().ok and audit.check().entries == 2


def test_a_lock_left_by_a_crashed_process_is_cleared(monkeypatch):
    monkeypatch.setenv("AUDIT_LOCK_MODE", "portable")
    lock = audit._portable_lock_path(audit.default_path())
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text("12345")
    long_ago = time.time() - 3600
    os.utime(lock, (long_ago, long_ago))
    audit.log({"event": "after the crash"})
    assert audit.check().entries == 1 and not lock.exists()


def test_waiting_for_a_busy_lock_times_out_instead_of_hanging(monkeypatch):
    monkeypatch.setenv("AUDIT_LOCK_MODE", "portable")
    monkeypatch.setattr(audit, "LOCK_TIMEOUT", 0.2)
    lock = audit._portable_lock_path(audit.default_path())
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text("someone else")                                     # fresh, so it is not 'stale'
    with pytest.raises(audit.AuditError, match="timed out"):
        audit.log({"event": "blocked"})
    assert not audit.default_path().exists() or audit.check().entries == 0
    assert lock.exists()                                                # we never delete a lock we do not own


def test_the_lock_is_released_even_when_the_log_is_damaged(monkeypatch):
    monkeypatch.setenv("AUDIT_LOCK_MODE", "portable")
    audit.log({"event": "ok"})
    with open(audit.default_path(), "ab") as handle:
        handle.write(b"half a line")                                    # no trailing newline
    with pytest.raises(audit.AuditCorruptError):
        audit.log({"event": "refused"})
    assert not audit._portable_lock_path(audit.default_path()).exists()
