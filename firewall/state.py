"""Config and memory of the firewall (Person 2 owns), issue #13.  HARDENED version.

Three jobs:
  1. LOAD the limits from rules.yaml, strictly                  -> load_rules()
  2. REMEMBER recent spending and recent actions                -> record_spend(), spent_last_24h(),
                                                                   record_action(), actions_in_window()
  3. HOLD the emergency kill switch                             -> set_kill_switch(), kill_switch_on()

This file is the firewall's MEMORY, so it is built to fail SAFE:
  * Unsure what a setting means?      -> refuse to start (load_rules raises ValueError). No guessing.
  * Strange amount?                   -> refuse it (never a negative, NaN, float or bool amount).
  * Cannot read the spending record?  -> raise, so the policy engine denies everything.
  * Cannot tell if the kill switch is on?  -> treat it as ON.
  * Rounding?                         -> always in the cautious direction (amounts round UP).

What it remembers, and where
  * Spending (daily cap)  : a small file, logs/spend_ledger.jsonl. Every line is chained with an HMAC, so
                            editing, deleting from the middle, or reordering lines is detected and the
                            firewall then refuses to run. It survives restarts (the daily cap cannot be reset
                            by restarting the app).
  * Kill switch           : a flag file, logs/kill_switch.flag. A restart does NOT un-freeze the wallet.
  * Velocity (actions)    : in memory only (a soft "ask" rule, not money).
Paths can be moved with SPEND_LEDGER_PATH and KILL_SWITCH_PATH (the tests do this).

Money is held as whole integers of the smallest unit (1 TUSD = 10**18), so there is no rounding at all.
Limits are ONE process at a time: do not run several server workers against the same files.
"""
import hashlib
import hmac
import json
import math
import os
import re
import tempfile
import threading
import time
from collections import deque
from decimal import ROUND_CEILING, Context, Decimal, localcontext
from pathlib import Path

import yaml

DEFAULT_RULES_PATH = Path(__file__).with_name("rules.yaml")
LOGS_DIR = Path(__file__).resolve().parents[1] / "logs"

DAY_SECONDS = 24 * 60 * 60
TOKEN_DECIMALS = 18
WEI = 10 ** TOKEN_DECIMALS                         # smallest units per 1 TUSD

MAX_LIMIT = Decimal(10) ** 12                      # no limit in rules.yaml may be bigger than this (TUSD)
MAX_AMOUNT_WEI = 10 ** 12 * WEI                    # no single recorded spend may be bigger than this
MAX_LEDGER_WEI = 10 ** 40                          # sanity bound for a (merged) ledger line
MAX_LEDGER_ENTRIES = 5000                          # if exceeded, the oldest entries are merged (never lost)
MAX_RULES_BYTES = 64 * 1024
MAX_VELOCITY_ACTIONS = 1000
MAX_VELOCITY_WINDOW = DAY_SECONDS
ACTION_MEMORY = 10_000                             # > MAX_VELOCITY_ACTIONS, so the count can never under-report

_LOCK = threading.RLock()


class StateError(Exception):
    """The firewall's memory could not be used safely. Callers must treat this as 'deny'."""


class StateCorruptError(StateError):
    """The spending record has been damaged or edited."""


def _clock() -> float:
    """Current time in seconds. A function of its own so tests can fake the time."""
    return time.time()


# =====================================================================================================
# 1. rules.yaml loader (strict)
# =====================================================================================================

_MONEY_RE = re.compile(r"(0|[1-9][0-9]{0,29})(\.[0-9]{1,18})?")      # ASCII only, no sign, no exponent
_ORIGIN_RE = re.compile(r"[A-Za-z0-9_.:\-]{1,64}")
_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_ZERO_ADDRESS = "0x" + "0" * 40
_KNOWN_KEYS = {"auto_limit", "max_tx", "daily_cap", "velocity", "trusted_origins", "chain_id", "allowlist"}


class _StrictLoader(yaml.SafeLoader):
    """Safe YAML loader that REFUSES a key written twice (plain YAML silently keeps the last one)."""

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise ValueError(f"the key {key!r} appears twice")
            seen.add(key)
        return super().construct_mapping(node, deep)


def _is_int(value) -> bool:
    return type(value) is int            # excludes bool (True is an int in Python!)


def load_rules(path=None) -> dict:
    """Read rules.yaml and return a clean dict. Raises ValueError (and ONLY ValueError) if anything is
    missing, unknown, mistyped or silly. Money limits must be written as quoted strings, e.g. "50".

    Returned keys: auto_limit, max_tx, daily_cap (Decimal), velocity_max_actions (int),
    velocity_window_seconds (int), trusted_origins (list), chain_id (int or None), allowlist (list).
    """
    rules_path = Path(path or os.getenv("RULES_PATH") or DEFAULT_RULES_PATH)
    try:
        with open(rules_path, "rb") as handle:
            data = handle.read(MAX_RULES_BYTES + 1)
        if len(data) > MAX_RULES_BYTES:
            raise ValueError(f"rules file is bigger than {MAX_RULES_BYTES} bytes")
        raw = yaml.load(data.decode("utf-8"), Loader=_StrictLoader)
    except ValueError as exc:                                 # includes UnicodeDecodeError
        raise ValueError(f"rules file cannot be used: {exc}") from None
    except (OSError, yaml.YAMLError, RecursionError) as exc:
        raise ValueError(f"rules file cannot be read ({type(exc).__name__})") from None

    if not isinstance(raw, dict) or not raw:
        raise ValueError("rules file must contain a list of settings (key: value)")
    unknown = set(raw) - _KNOWN_KEYS
    if unknown:
        raise ValueError(f"rules file has unknown setting(s): {sorted(map(str, unknown))} (typo?)")

    def money(name: str) -> Decimal:
        if name not in raw:
            raise ValueError(f"rules file is missing '{name}'")
        value = raw[name]
        if not isinstance(value, str) or not _MONEY_RE.fullmatch(value):
            raise ValueError(f"'{name}' must be a plain number written in quotes, like \"50\" (got {value!r})")
        number = Decimal(value)
        if number > MAX_LIMIT:
            raise ValueError(f"'{name}' is unreasonably large (more than {MAX_LIMIT})")
        return number

    auto_limit, max_tx, daily_cap = money("auto_limit"), money("max_tx"), money("daily_cap")
    if auto_limit > max_tx:
        raise ValueError("auto_limit cannot be bigger than max_tx")

    velocity = raw.get("velocity")
    if not isinstance(velocity, dict) or set(velocity) != {"max_actions", "window_seconds"}:
        raise ValueError("'velocity' needs exactly: max_actions and window_seconds")
    max_actions, window_seconds = velocity["max_actions"], velocity["window_seconds"]
    if not (_is_int(max_actions) and 1 <= max_actions <= MAX_VELOCITY_ACTIONS):
        raise ValueError(f"velocity max_actions must be a whole number from 1 to {MAX_VELOCITY_ACTIONS}")
    if not (_is_int(window_seconds) and 1 <= window_seconds <= MAX_VELOCITY_WINDOW):
        raise ValueError(f"velocity window_seconds must be a whole number from 1 to {MAX_VELOCITY_WINDOW}")

    origins = raw.get("trusted_origins")
    origins = [] if origins is None else origins
    if not isinstance(origins, list) or not all(isinstance(o, str) and _ORIGIN_RE.fullmatch(o) for o in origins):
        raise ValueError("'trusted_origins' must be a list of plain names like user_chat")

    chain_id = raw.get("chain_id")
    if chain_id is not None and not (_is_int(chain_id) and 1 <= chain_id < 2 ** 64):
        raise ValueError("'chain_id' must be a positive whole number (or null)")

    allowlist = raw.get("allowlist")
    allowlist = [] if allowlist is None else allowlist
    if not isinstance(allowlist, list) or len(allowlist) > 1000:
        raise ValueError("'allowlist' must be a list of addresses")
    for address in allowlist:
        if not isinstance(address, str) or not _ADDRESS_RE.fullmatch(address):
            raise ValueError(f"allowlist entry {address!r} is not a valid address (0x + 40 hex characters)")
        if address.lower() == _ZERO_ADDRESS:
            raise ValueError("the zero address must not be on the allowlist")

    return {
        "auto_limit": auto_limit,
        "max_tx": max_tx,
        "daily_cap": daily_cap,
        "velocity_max_actions": max_actions,
        "velocity_window_seconds": window_seconds,
        "trusted_origins": list(origins),
        "chain_id": chain_id,
        "allowlist": list(allowlist),
    }


# =====================================================================================================
# 2a. spending memory: a durable, tamper-evident ledger
# =====================================================================================================

def _ledger_path() -> Path:
    env = os.getenv("SPEND_LEDGER_PATH")
    return Path(env) if env else LOGS_DIR / "spend_ledger.jsonl"


def _ledger_key() -> bytes:
    secret = os.getenv("APPROVAL_SECRET", "")
    if len(secret) < 16:
        raise StateError("APPROVAL_SECRET is missing or too short, so the spending record cannot be protected")
    return hmac.new(secret.encode("utf-8"), b"sentinel-wallet/spend-ledger/v1", hashlib.sha256).digest()


def _mac(key: bytes, prev: str, ts: float, wei: int) -> str:
    body = json.dumps([prev, ts, wei], separators=(",", ":"))
    return hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest()


_GENESIS = "0" * 64


def _load_ledger(key: bytes):
    """Read and VERIFY the whole ledger. Returns (entries, last_mac). entries = [(ts, wei), ...].
    Any damage -> StateCorruptError (the firewall then refuses to act)."""
    path = _ledger_path()
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return [], _GENESIS
    except OSError as exc:
        raise StateError(f"the spending record cannot be read ({type(exc).__name__})") from None
    if not data:
        return [], _GENESIS
    if not data.endswith(b"\n"):
        raise StateCorruptError("the spending record ends in a half-written line")

    entries, prev = [], _GENESIS
    for number, line in enumerate(data.split(b"\n")[:-1], start=1):
        try:
            item = json.loads(line.decode("utf-8"))
            ts, wei, mac = item["ts"], item["wei"], item["mac"]
            ok = (isinstance(item, dict) and set(item) == {"ts", "wei", "mac"}
                  and type(ts) in (int, float) and math.isfinite(ts)
                  and _is_int(wei) and 1 <= wei <= MAX_LEDGER_WEI
                  and isinstance(mac, str) and len(mac) == 64)
            if not ok or not hmac.compare_digest(mac, _mac(key, prev, ts, wei)):
                raise ValueError
        except Exception:
            raise StateCorruptError(f"the spending record was edited or damaged (line {number})") from None
        entries.append((ts, wei))
        prev = mac
    return entries, prev


def _chain(key: bytes, entries):
    """Turn [(ts, wei)] into ledger lines (bytes), chained from the start."""
    prev, out = _GENESIS, []
    for ts, wei in entries:
        mac = _mac(key, prev, ts, wei)
        out.append(json.dumps({"ts": ts, "wei": wei, "mac": mac}, separators=(",", ":")).encode("utf-8") + b"\n")
        prev = mac
    return out


def _write_atomic(path: Path, lines) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as out:
            out.writelines(lines)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _to_wei(amount) -> int:
    """TUSD amount -> whole smallest units, rounded UP. Accepts str / int / Decimal only.
    Raises TypeError for float, bool, None...; ValueError for negative, NaN, infinite, absurd or odd text."""
    if isinstance(amount, bool) or not isinstance(amount, (str, int, Decimal)):
        raise TypeError(f"an amount must be a string, whole number or Decimal, not {type(amount).__name__}")
    with localcontext(Context(prec=200)):
        if isinstance(amount, str):
            if len(amount) > 100 or not re.fullmatch(r"[0-9]+(\.[0-9]+)?", amount):
                raise ValueError(f"not a valid amount: {amount[:40]!r}")
            value = Decimal(amount)
        else:
            value = Decimal(amount)
        if not value.is_finite() or value < 0:
            raise ValueError("an amount must be a finite number, zero or more")
        wei = int(value.scaleb(TOKEN_DECIMALS).to_integral_value(rounding=ROUND_CEILING))
    if wei > MAX_AMOUNT_WEI:
        raise ValueError("amount is unreasonably large")
    return wei


def _wei_to_decimal(wei: int) -> Decimal:
    whole, frac = divmod(wei, WEI)
    text = f"{whole}.{frac:018d}".rstrip("0").rstrip(".")
    return Decimal(text)


def record_spend(amount) -> None:
    """Remember that `amount` TUSD may leave the wallet (called when a token is issued).
    The note is written to disk (and flushed) before this returns. Zero is ignored."""
    wei = _to_wei(amount)
    if wei == 0:
        return
    with _LOCK:
        key = _ledger_key()
        entries, last_mac = _load_ledger(key)
        now = _clock()
        live = [e for e in entries if now - e[0] <= DAY_SECONDS]       # entries from the future are kept
        path = _ledger_path()
        if len(live) == len(entries) and len(live) + 1 <= MAX_LEDGER_ENTRIES:
            mac = _mac(key, last_mac, now, wei)                         # chained to the previous line
            line = json.dumps({"ts": now, "wei": wei, "mac": mac}, separators=(",", ":")).encode("utf-8") + b"\n"
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "ab") as out:
                out.write(line)
                out.flush()
                os.fsync(out.fileno())
            return
        # something expired, or the file is full: rewrite it compactly (atomically)
        live.append((now, wei))
        live.sort(key=lambda e: e[0])
        while len(live) > MAX_LEDGER_ENTRIES:         # merge the two oldest; the newer time is kept, so the
            a, b = live[0], live[1]                    # money is counted for LONGER, never for shorter
            live[0:2] = [(max(a[0], b[0]), a[1] + b[1])]
        _write_atomic(path, _chain(key, live))


def spent_last_24h() -> Decimal:
    """Total TUSD recorded during the last 24 hours (entries exactly 24h old still count)."""
    with _LOCK:
        entries, _ = _load_ledger(_ledger_key())
        now = _clock()
        total = sum(wei for ts, wei in entries if now - ts <= DAY_SECONDS)
    return _wei_to_decimal(total)


# =====================================================================================================
# 2b. velocity memory (in memory only)
# =====================================================================================================

_ACTIONS = deque(maxlen=ACTION_MEMORY)


def record_action() -> None:
    """Remember that one action was requested (used for the 'too many actions' rule VEL-01)."""
    with _LOCK:
        _ACTIONS.append(_clock())


def actions_in_window(window_seconds=None) -> int:
    """How many actions happened in the last `window_seconds` (default: the window in rules.yaml).
    Only the newest ACTION_MEMORY actions are kept, which is always enough to know 'at least max_actions'."""
    if window_seconds is None:
        window_seconds = load_rules()["velocity_window_seconds"]
    if not (_is_int(window_seconds) and 1 <= window_seconds <= MAX_VELOCITY_WINDOW):
        raise ValueError(f"window_seconds must be a whole number from 1 to {MAX_VELOCITY_WINDOW}")
    with _LOCK:
        now = _clock()
        return sum(1 for ts in _ACTIONS if now - ts <= window_seconds)


# =====================================================================================================
# 3. kill switch (survives restarts, fails safe)
# =====================================================================================================

_KILL_SWITCH = False


def _flag_path() -> Path:
    env = os.getenv("KILL_SWITCH_PATH")
    return Path(env) if env else LOGS_DIR / "kill_switch.flag"


def set_kill_switch(on) -> None:
    """Turn the emergency stop on or off.
    ONLY the real value False turns it off. True, None, 0, "false", ... all turn it ON: when unsure, freeze.
    It also writes/removes a flag file, so a restart does not silently un-freeze the wallet."""
    global _KILL_SWITCH
    with _LOCK:
        path = _flag_path()
        if on is False:
            try:
                path.unlink(missing_ok=True)
                still_there = path.exists()
            except OSError:
                still_there = True
            if still_there:
                raise StateError("could not remove the kill-switch flag file, so the wallet stays FROZEN")
            _KILL_SWITCH = False
            return
        _KILL_SWITCH = True                                   # frozen first, saved second
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("ON\n", encoding="utf-8")
        except OSError:
            raise StateError("the wallet is FROZEN now, but the flag file could not be saved (a restart would unfreeze it)") from None


def kill_switch_on() -> bool:
    """True if the wallet is frozen. If this cannot be determined, it says True."""
    if _KILL_SWITCH:
        return True
    try:
        return _flag_path().exists()
    except Exception:
        return True


# =====================================================================================================
# tests only
# =====================================================================================================

def reset() -> None:
    """Forget everything (spend record, actions, kill switch). TESTS ONLY: it refuses to run outside pytest,
    and refuses to touch the real files (the tests must point SPEND_LEDGER_PATH and KILL_SWITCH_PATH elsewhere)."""
    global _KILL_SWITCH
    if "PYTEST_CURRENT_TEST" not in os.environ:
        raise RuntimeError("state.reset() is only for tests")
    if not (os.getenv("SPEND_LEDGER_PATH") and os.getenv("KILL_SWITCH_PATH")):
        raise RuntimeError("state.reset() needs SPEND_LEDGER_PATH and KILL_SWITCH_PATH set (see tests/conftest.py)")
    with _LOCK:
        _ACTIONS.clear()
        _KILL_SWITCH = False
        _ledger_path().unlink(missing_ok=True)
        _flag_path().unlink(missing_ok=True)