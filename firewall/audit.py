"""Tamper-evident audit log (issue #17).

An append-only JSON-Lines file. Every line is one entry:

    {"seq": 0, "ts": "2026-10-15T17:30:00Z", "event": {...}, "prev_hash": "<64 hex>", "hash": "<64 hex>"}

`hash` is SHA-256 over {seq, ts, event, prev_hash} (canonical JSON), and `prev_hash` is the `hash` of
the previous line (64 zeros for the first). Editing, deleting, inserting or re-ordering any line
breaks the chain and verify() returns False.

What this proves, and what it does not
  * It is TAMPER-EVIDENT, not tamper-proof. Someone who can rewrite the whole file can also
    recompute every hash.
  * Deleting the LAST entries leaves a perfectly valid shorter chain. To detect that, keep the
    head hash somewhere else (screenshot, evidence file, the UI) and pass it as `expected_head`.

Where the file lives: $AUDIT_LOG_PATH, default `<repo>/logs/audit.jsonl` (git-ignored; copy it into
evidence/ when you want to submit it).

Safety
  * Values under keys that look like secrets (private key, secret, api key, password, approval
    token, mnemonic, seed) are replaced with "[REDACTED]" before anything is written.
  * Appends are serialised by a thread lock and a cross-process lock on <log>.lock (flock on Linux/macOS,
    msvcrt.locking on Windows, an exclusive-create <log>.plock file anywhere else), so several threads or
    processes can write the same log without breaking the chain.
  * A log whose last line is damaged is NOT extended silently: log() raises AuditCorruptError.

Command line:  python scripts/verify_audit.py [path]      (or: python scripts/verify_audit.py tail)
"""
import contextlib
import hashlib
import json
import os
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:                      # Linux / macOS
    import fcntl
except ImportError:       # pragma: no cover
    fcntl = None
try:                      # Windows
    import msvcrt
except ImportError:
    msvcrt = None

GENESIS = "0" * 64
_KEYS = {"seq", "ts", "event", "prev_hash", "hash"}
_SENSITIVE = ("private_key", "secret", "api_key", "password", "approval_token", "mnemonic", "seed")
_LOCK = threading.Lock()
LOCK_TIMEOUT = 30.0        # seconds to wait for another process to finish its append
STALE_LOCK_SECONDS = 15.0  # a portable lock file older than this was left behind by a crashed process


class AuditError(RuntimeError):
    """Base class for audit-log problems."""


class AuditCorruptError(AuditError):
    """The existing log is damaged; refusing to extend it."""


@dataclass
class AuditCheck:
    ok: bool
    entries: int
    head: str | None          # hash of the last entry, or None for an empty log
    reason: str | None = None
    line: int | None = None   # 1-based line number of the first problem


# ------------------------------------------------------------------ helpers

def default_path() -> Path:
    env = os.getenv("AUDIT_LOG_PATH")
    return Path(env) if env else Path(__file__).resolve().parents[1] / "logs" / "audit.jsonl"


def _entry_hash(seq: int, ts: str, event: dict, prev_hash: str) -> str:
    body = json.dumps({"seq": seq, "ts": ts, "event": event, "prev_hash": prev_hash},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _redact(value):
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if any(word in str(key).lower() for word in _SENSITIVE):
                out[str(key)] = "[REDACTED]"
            else:
                out[str(key)] = _redact(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value


def _normalize(event: dict) -> dict:
    """Redact secrets and round-trip through JSON so what is hashed is exactly what is read back."""
    return json.loads(json.dumps(_redact(event), default=str, sort_keys=True, allow_nan=False))


def _lock_mode() -> str:
    """Which cross-process lock to use: "fcntl" (Linux/macOS), "msvcrt" (Windows) or "portable".

    AUDIT_LOCK_MODE can force one (used by the tests to exercise the Windows / fallback paths on Linux).
    A forced mode that this system does not have falls back to "portable".
    """
    forced = os.getenv("AUDIT_LOCK_MODE", "").strip().lower()
    if forced == "fcntl" and fcntl is not None:
        return "fcntl"
    if forced == "msvcrt" and msvcrt is not None:
        return "msvcrt"
    if forced in ("fcntl", "msvcrt", "portable"):
        return "portable"
    if fcntl is not None:
        return "fcntl"
    if msvcrt is not None:
        return "msvcrt"
    return "portable"


def _lock_path(path: Path) -> Path:
    """Lock file for flock / msvcrt.locking (the file itself is never deleted)."""
    return path.with_name(path.name + ".lock")


def _portable_lock_path(path: Path) -> Path:
    """A DIFFERENT name for the portable lock: its existence IS the lock, so it must never be a file that
    flock / msvcrt.locking merely opened (that would make the fallback wait for a lock nobody holds)."""
    return path.with_name(path.name + ".plock")


def _wait_or_fail(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise AuditError("timed out waiting for another process to finish writing the audit log")
    time.sleep(0.005)


@contextlib.contextmanager
def _fcntl_lock(path: Path):
    """flock on a separate lock file. Yields False if this file system has no flock (the caller falls back)."""
    with open(_lock_path(path), "a+b") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except OSError:       # some network / FUSE file systems have no flock
            yield False
            return
        try:
            yield True
        finally:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass


@contextlib.contextmanager
def _msvcrt_lock(path: Path):
    """Windows: lock one byte of a separate lock file (msvcrt.locking), waiting politely until it is free."""
    with open(_lock_path(path), "a+b") as handle:
        if handle.seek(0, os.SEEK_END) == 0:
            handle.write(b"\0")          # the locked byte must exist
            handle.flush()
        deadline = time.monotonic() + LOCK_TIMEOUT
        while True:
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                _wait_or_fail(deadline)
        try:
            yield
        finally:
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass


@contextlib.contextmanager
def _portable_lock(path: Path):
    """Last resort that needs nothing from the OS: the lock IS a file created exclusively (O_EXCL).

    Whoever creates it owns the lock; deleting it releases the lock. A lock file left behind by a crashed
    process is removed once it is older than STALE_LOCK_SECONDS (an append takes milliseconds).
    """
    lock = _portable_lock_path(path)
    deadline = time.monotonic() + LOCK_TIMEOUT
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(lock) > STALE_LOCK_SECONDS:
                    os.unlink(lock)
                    continue
            except OSError:        # it vanished between the two calls: just try again
                continue
            _wait_or_fail(deadline)
            continue
        os.write(fd, str(os.getpid()).encode("ascii"))
        os.close(fd)
        break
    try:
        yield
    finally:
        try:
            os.unlink(lock)
        except FileNotFoundError:
            pass


@contextlib.contextmanager
def _cross_process_lock(path: Path):
    """Hold a lock that other PROCESSES also respect for the whole read-last-line-then-append step."""
    mode = _lock_mode()
    if mode == "fcntl":
        with _fcntl_lock(path) as locked:
            if locked:
                yield
                return
        mode = "portable"        # no flock here: do NOT carry on unlocked, use the portable lock instead
    if mode == "msvcrt":
        with _msvcrt_lock(path):
            yield
    else:
        with _portable_lock(path):
            yield


def _parse(raw: bytes) -> dict:
    entry = json.loads(raw.decode("utf-8"))
    if not isinstance(entry, dict) or set(entry) != _KEYS:
        raise ValueError("unexpected fields")
    if not isinstance(entry["seq"], int) or isinstance(entry["seq"], bool):
        raise ValueError("seq is not an integer")
    for key in ("ts", "prev_hash", "hash"):
        if not isinstance(entry[key], str):
            raise ValueError(f"{key} is not a string")
    if not isinstance(entry["event"], dict):
        raise ValueError("event is not an object")
    return entry


def _last_line(handle) -> bytes | None:
    """The last line of an open log file (None if empty). Raises if the file does not end cleanly."""
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    if size == 0:
        return None
    position, step, data = size, 4096, b""
    while position > 0:
        read = min(step, position)
        position -= read
        handle.seek(position)
        data = handle.read(read) + data
        if b"\n" in data.rstrip(b"\n"):
            break
        step *= 2
    if not data.endswith(b"\n"):
        raise AuditCorruptError("the last line of the audit log is incomplete")
    if data.endswith(b"\n\n"):
        raise AuditCorruptError("the audit log ends with a blank line")
    return data.rstrip(b"\n").split(b"\n")[-1]


# ------------------------------------------------------------------ public API

def log(event: dict) -> None:
    """Append one event. Raises TypeError for a non-dict, AuditCorruptError for a damaged log."""
    if not isinstance(event, dict):
        raise TypeError("an audit event must be a dict")
    normalized = _normalize(event)
    path = default_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    with _LOCK:                                  # other threads of this process
        with _cross_process_lock(path):          # other processes (Linux, macOS and Windows)
            with open(path, "a+b") as handle:
                raw_last = _last_line(handle)
                if raw_last is None:
                    seq, prev_hash = 0, GENESIS
                else:
                    try:
                        last = _parse(raw_last)
                    except ValueError as exc:
                        raise AuditCorruptError(f"the last audit entry is unreadable: {exc}")
                    if _entry_hash(last["seq"], last["ts"], last["event"], last["prev_hash"]) != last["hash"]:
                        raise AuditCorruptError("the last audit entry does not match its hash")
                    seq, prev_hash = last["seq"] + 1, last["hash"]
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                entry = {"seq": seq, "ts": ts, "event": normalized, "prev_hash": prev_hash,
                         "hash": _entry_hash(seq, ts, normalized, prev_hash)}
                handle.write((json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())


def check(path: str | os.PathLike | None = None, expected_head: str | None = None) -> AuditCheck:
    """Walk the whole chain and say what is wrong, if anything."""
    target = Path(path) if path else default_path()
    if not target.exists():
        if expected_head is None:
            return AuditCheck(True, 0, None)
        return AuditCheck(False, 0, None, "the log file is missing but a head hash was expected")
    data = target.read_bytes()
    if not data:
        if expected_head is None:
            return AuditCheck(True, 0, None)
        return AuditCheck(False, 0, None, "the log is empty but a head hash was expected")
    if not data.endswith(b"\n"):
        return AuditCheck(False, 0, None, "the last line is incomplete", line=data.count(b"\n") + 1)

    prev_hash, count = GENESIS, 0
    for number, raw in enumerate(data.split(b"\n")[:-1], start=1):
        if not raw:
            return AuditCheck(False, count, None, "blank line", line=number)
        try:
            entry = _parse(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            return AuditCheck(False, count, None, f"line is not a valid entry: {exc}", line=number)
        if entry["seq"] != count:
            return AuditCheck(False, count, None, f"entry number is {entry['seq']}, expected {count} "
                              "(a line was deleted, inserted or moved)", line=number)
        if entry["prev_hash"] != prev_hash:
            return AuditCheck(False, count, None, "does not link to the previous entry", line=number)
        if _entry_hash(entry["seq"], entry["ts"], entry["event"], entry["prev_hash"]) != entry["hash"]:
            return AuditCheck(False, count, None, "the entry was modified (hash mismatch)", line=number)
        prev_hash, count = entry["hash"], count + 1

    if expected_head is not None and expected_head != prev_hash:
        return AuditCheck(False, count, prev_hash,
                          "the head hash differs from the one you expected (entries were removed or replaced)")
    return AuditCheck(True, count, prev_hash)


def verify(path: str | os.PathLike | None = None, expected_head: str | None = None) -> bool:
    """True only if the whole chain is intact (and, when given, ends at expected_head)."""
    return check(path, expected_head).ok


def head(path: str | os.PathLike | None = None) -> dict | None:
    """{'seq', 'hash'} of the newest entry, or None if the log is empty. Store it elsewhere to detect truncation."""
    result = check(path)
    return {"seq": result.entries - 1, "hash": result.head} if result.ok and result.entries else None


def tail(n: int = 50, path: str | os.PathLike | None = None) -> list[dict]:
    """The newest n entries (oldest first) for the UI viewer. Unreadable lines are skipped; use verify() for trust."""
    target = Path(path) if path else default_path()
    if not target.exists():
        return []
    entries = []
    for raw in target.read_bytes().split(b"\n"):
        if raw:
            try:
                entries.append(_parse(raw))
            except (ValueError, UnicodeDecodeError):
                continue
    return entries[-n:] if n > 0 else []


# ------------------------------------------------------------------ command line

def _main(argv: list[str]) -> int:
    command = argv[1] if len(argv) > 1 else "verify"
    path = argv[2] if len(argv) > 2 else None
    if command == "verify":
        result = check(path)
        where = Path(path) if path else default_path()
        if result.ok:
            print(f"OK: {result.entries} entries, head {result.head or '(empty)'}   [{where}]")
            return 0
        print(f"FAILED: {result.reason} (line {result.line})   [{where}]")
        return 1
    if command == "tail":
        for entry in tail(10, path):
            print(f"{entry['seq']:>5}  {entry['ts']}  {json.dumps(entry['event'], sort_keys=True)}")
        return 0
    print("usage: python -m firewall.audit [verify|tail] [path]")
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
