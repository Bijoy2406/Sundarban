"""Tests for firewall/state.py (issue #13): rules loader, daily spend, velocity, kill switch."""
from decimal import Decimal

import pytest

from firewall import state


@pytest.fixture(autouse=True)
def clean_state():
    state.reset()
    yield
    state.reset()


def _write_rules(tmp_path, text):
    path = tmp_path / "rules.yaml"
    path.write_text(text)
    return path


GOOD = """
auto_limit: "50"
max_tx: "500"
daily_cap: "1000"
velocity:
  max_actions: 5
  window_seconds: 600
trusted_origins: [user_chat]
chain_id: null
allowlist: []
"""


# ---- loader ----
def test_real_rules_file_loads():
    rules = state.load_rules()
    assert rules["auto_limit"] == Decimal("50")
    assert rules["max_tx"] == Decimal("500")
    assert rules["daily_cap"] == Decimal("1000")
    assert rules["velocity_max_actions"] == 5
    assert rules["velocity_window_seconds"] == 600
    assert rules["trusted_origins"] == ["user_chat"]


def test_limits_are_decimal_not_float():
    rules = state.load_rules()
    assert all(isinstance(rules[k], Decimal) for k in ("auto_limit", "max_tx", "daily_cap"))


def test_missing_value_is_rejected(tmp_path):
    path = _write_rules(tmp_path, GOOD.replace('daily_cap: "1000"\n', ""))
    with pytest.raises(ValueError):
        state.load_rules(path)


def test_negative_or_text_limit_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        state.load_rules(_write_rules(tmp_path, GOOD.replace('"50"', '"-5"')))
    with pytest.raises(ValueError):
        state.load_rules(_write_rules(tmp_path, GOOD.replace('"50"', '"lots"')))


def test_auto_limit_above_max_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        state.load_rules(_write_rules(tmp_path, GOOD.replace('"50"', '"900"')))


def test_bad_velocity_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        state.load_rules(_write_rules(tmp_path, GOOD.replace("max_actions: 5", "max_actions: 0")))


# ---- daily spend ----
def test_daily_spend_adds_up():
    state.record_spend("10.5", now=1000)
    state.record_spend(Decimal("20"), now=1100)
    assert state.spent_last_24h(now=1200) == Decimal("30.5")


def test_old_spend_drops_out_after_24h():
    state.record_spend("100", now=0)
    state.record_spend("5", now=state.DAY_SECONDS)
    assert state.spent_last_24h(now=state.DAY_SECONDS + 1) == Decimal("5")


def test_no_spend_is_zero():
    assert state.spent_last_24h() == Decimal(0)


# ---- velocity ----
def test_velocity_counts_only_inside_window():
    for t in (0, 100, 200):
        state.record_action(now=t)
    assert state.actions_in_window(window_seconds=600, now=300) == 3
    assert state.actions_in_window(window_seconds=600, now=750) == 1   # only t=200 is still inside


def test_velocity_uses_rules_window_by_default():
    state.record_action(now=1000)
    assert state.actions_in_window(now=1000 + 599) == 1
    assert state.actions_in_window(now=1000 + 601) == 0


# ---- kill switch ----
def test_kill_switch_on_off():
    assert state.kill_switch_on() is False
    state.set_kill_switch(True)
    assert state.kill_switch_on() is True
    state.set_kill_switch(False)
    assert state.kill_switch_on() is False