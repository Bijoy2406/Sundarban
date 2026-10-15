"""Config and runtime state for the firewall (Person 2 owns), issue #13.

Three jobs:
  1. LOAD the limits from firewall/rules.yaml        -> load_rules()
  2. REMEMBER recent spending and recent actions     -> record_spend(), spent_last_24h(),
                                                        record_action(), actions_in_window()
  3. HOLD the emergency kill switch                  -> set_kill_switch(), kill_switch_on()

The policy engine (policy.py, issue #15) will ask this file questions such as
"how much was spent in the last 24 hours?" and "is the kill switch on?".

Memory is in-process only: restarting the app starts with a clean slate. That is fine for the demo.
Money is always Decimal (never float), as the project rules say.
"""
import os
import time
from decimal import Decimal
from pathlib import Path

import yaml

DEFAULT_RULES_PATH = Path(__file__).with_name("rules.yaml")
DAY_SECONDS = 24 * 60 * 60

# ---- 1. rules.yaml loader ---------------------------------------------------------------------


def load_rules(path=None) -> dict:
    """Read rules.yaml and return a clean dict. Raises ValueError if a value is missing or silly.

    Returned keys: auto_limit, max_tx, daily_cap (all Decimal), velocity_max_actions (int),
    velocity_window_seconds (int), trusted_origins (list), chain_id (int or None), allowlist (list).
    """
    rules_path = Path(path or os.getenv("RULES_PATH") or DEFAULT_RULES_PATH)
    with open(rules_path, "r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    def money(name: str) -> Decimal:
        if name not in raw:
            raise ValueError(f"rules.yaml is missing '{name}'")
        try:
            value = Decimal(str(raw[name]))
        except Exception:
            raise ValueError(f"rules.yaml: '{name}' must be a number, got {raw[name]!r}")
        if not value.is_finite() or value < 0:
            raise ValueError(f"rules.yaml: '{name}' must be zero or more, got {raw[name]!r}")
        return value

    auto_limit, max_tx, daily_cap = money("auto_limit"), money("max_tx"), money("daily_cap")
    if auto_limit > max_tx:
        raise ValueError("rules.yaml: auto_limit cannot be bigger than max_tx")

    velocity = raw.get("velocity") or {}
    try:
        max_actions = int(velocity["max_actions"])
        window_seconds = int(velocity["window_seconds"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("rules.yaml: 'velocity' needs whole numbers max_actions and window_seconds")
    if max_actions < 1 or window_seconds < 1:
        raise ValueError("rules.yaml: velocity numbers must be at least 1")

    chain_id = raw.get("chain_id")
    return {
        "auto_limit": auto_limit,
        "max_tx": max_tx,
        "daily_cap": daily_cap,
        "velocity_max_actions": max_actions,
        "velocity_window_seconds": window_seconds,
        "trusted_origins": [str(o) for o in (raw.get("trusted_origins") or [])],
        "chain_id": int(chain_id) if chain_id is not None else None,
        "allowlist": [str(a) for a in (raw.get("allowlist") or [])],
    }


# ---- 2. spending and velocity memory ------------------------------------------------------------

_SPENDS = []     # list of (unix_time, Decimal amount) for money that really left the wallet
_ACTIONS = []    # list of unix times, one per action the firewall handled


def record_spend(amount, now=None) -> None:
    """Remember that `amount` TUSD was really sent (call this after a transfer succeeds)."""
    _SPENDS.append((time.time() if now is None else now, Decimal(str(amount))))


def spent_last_24h(now=None) -> Decimal:
    """Total TUSD sent during the last 24 hours."""
    now = time.time() if now is None else now
    return sum((amt for ts, amt in _SPENDS if now - ts < DAY_SECONDS), Decimal(0))


def record_action(now=None) -> None:
    """Remember that one action was requested (used for the 'too many actions' rule VEL-01)."""
    _ACTIONS.append(time.time() if now is None else now)


def actions_in_window(window_seconds=None, now=None) -> int:
    """How many actions happened in the last `window_seconds` (default: the window in rules.yaml)."""
    if window_seconds is None:
        window_seconds = load_rules()["velocity_window_seconds"]
    now = time.time() if now is None else now
    return sum(1 for ts in _ACTIONS if now - ts < window_seconds)


# ---- 3. kill switch -------------------------------------------------------------------------------

_KILL_SWITCH = False


def set_kill_switch(on: bool) -> None:
    global _KILL_SWITCH
    _KILL_SWITCH = bool(on)


def kill_switch_on() -> bool:
    return _KILL_SWITCH


def reset() -> None:
    """Forget everything (spend, actions, kill switch). Used by tests."""
    _SPENDS.clear()
    _ACTIONS.clear()
    set_kill_switch(False)