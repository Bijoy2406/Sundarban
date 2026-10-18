"""Tests for firewall/state.py (issue #13): the firewall's MEMORY.

Sections: rules loader (valid / invalid / fuzz) - amounts - 24h window - tamper-evident ledger -
restarts - velocity - kill switch - concurrency - differential (model-based) test - API hygiene.
"""
import json
import os
import random
import subprocess
import sys
import threading
from collections import deque
from decimal import Decimal
from fractions import Fraction
from math import ceil
from pathlib import Path

import pytest

from firewall import state

ROOT = Path(__file__).resolve().parents[1]
DAY = state.DAY_SECONDS
ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

GOOD = """auto_limit: "50"
max_tx: "500"
daily_cap: "1000"
velocity:
  max_actions: 5
  window_seconds: 600
trusted_origins: [user_chat]
chain_id: null
allowlist: []
"""


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(state, "_clock", c)
    return c


def rules_file(tmp_path, text):
    path = tmp_path / "rules.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def load(tmp_path, text):
    return state.load_rules(rules_file(tmp_path, text))


def ledger_lines():
    return Path(os.environ["SPEND_LEDGER_PATH"]).read_bytes().split(b"\n")[:-1]


def wei(text):
    return int(Decimal(text).scaleb(18))


# =====================================================================================================
# 1. rules loader
# =====================================================================================================

def test_real_rules_file_loads():
    rules = state.load_rules()
    assert rules["auto_limit"] == Decimal("50") and rules["max_tx"] == Decimal("500")
    assert rules["daily_cap"] == Decimal("1000")
    assert rules["velocity_max_actions"] == 5 and rules["velocity_window_seconds"] == 600
    assert rules["trusted_origins"] == ["user_chat"]


def test_good_document_gives_the_right_types(tmp_path):
    r = load(tmp_path, GOOD)
    assert all(type(r[k]) is Decimal for k in ("auto_limit", "max_tx", "daily_cap"))
    assert type(r["velocity_max_actions"]) is int and type(r["velocity_window_seconds"]) is int
    assert r["chain_id"] is None and r["allowlist"] == [] and r["trusted_origins"] == ["user_chat"]


def test_optional_keys_may_be_left_out(tmp_path):
    text = GOOD.replace("trusted_origins: [user_chat]\n", "").replace("chain_id: null\n", "").replace("allowlist: []\n", "")
    r = load(tmp_path, text)
    assert r["trusted_origins"] == [] and r["chain_id"] is None and r["allowlist"] == []


def test_returned_lists_are_fresh_copies(tmp_path):
    path = rules_file(tmp_path, GOOD)
    first = state.load_rules(path)
    first["trusted_origins"].append("evil")
    assert state.load_rules(path)["trusted_origins"] == ["user_chat"]


def test_rules_path_environment_variable_is_used(monkeypatch, tmp_path):
    monkeypatch.setenv("RULES_PATH", str(rules_file(tmp_path, GOOD.replace('"500"', '"600"'))))
    assert state.load_rules()["max_tx"] == Decimal("600")


@pytest.mark.parametrize("value,expected", [("0", "0"), ("50", "50"), ("0.5", "0.5"), ("12.345", "12.345"),
                                            ("0.000000000000000001", "0.000000000000000001"),
                                            ("1000000000000", "1000000000000")])
def test_valid_money_values(tmp_path, value, expected):
    assert load(tmp_path, GOOD.replace('"1000"', f'"{value}"'))["daily_cap"] == Decimal(expected)


BAD_MONEY = [
    "-1", "+5", " 5", "5 ", "", ".5", "5.", "05", "050", "0500", "00", "1e3", "5E2", "1_000", "1,000",
    "0x10", "NaN", "nan", "Infinity", "inf", "-0", "abc", "5 0",
    "０", "５０", "٥٠", "५०", "5０", "1٥", "1.５", "0.٥", "1०",   # other scripts' digits that Python's Decimal accepts
    "0.0000000000000000001",                                    # 19 decimals: finer than the token
    "1000000000001",                                            # bigger than MAX_LIMIT
    "9" * 31,
]


@pytest.mark.parametrize("value", BAD_MONEY)
def test_bad_money_text_is_rejected(tmp_path, value):
    with pytest.raises(ValueError):
        load(tmp_path, GOOD.replace('"1000"', json.dumps(value)))


@pytest.mark.parametrize("literal", ["1000", "1000.5", "0500", "true", "null", "[1000]", "{a: 1}", "0x3E8", ".inf", ".nan", "1e3"])
def test_money_must_be_a_quoted_string(tmp_path, literal):
    with pytest.raises(ValueError):
        load(tmp_path, GOOD.replace('"1000"', literal))


@pytest.mark.parametrize("key", ["auto_limit", "max_tx", "daily_cap", "velocity"])
def test_missing_required_key_is_rejected(tmp_path, key):
    lines = [l for l in GOOD.splitlines() if not l.startswith(key)]
    if key == "velocity":
        lines = [l for l in lines if not l.startswith("  ")]
    with pytest.raises(ValueError):
        load(tmp_path, "\n".join(lines) + "\n")


def test_auto_limit_above_max_tx_is_rejected_but_equal_is_fine(tmp_path):
    with pytest.raises(ValueError):
        load(tmp_path, GOOD.replace('"50"', '"501"'))
    assert load(tmp_path, GOOD.replace('"50"', '"500"'))["auto_limit"] == Decimal("500")


def test_zero_limits_are_allowed(tmp_path):
    r = load(tmp_path, GOOD.replace('"50"', '"0"').replace('"500"', '"0"').replace('"1000"', '"0"'))
    assert r["max_tx"] == 0


def test_duplicate_key_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        load(tmp_path, GOOD + 'daily_cap: "99999"\n')
    with pytest.raises(ValueError):
        load(tmp_path, GOOD.replace("  window_seconds: 600", "  window_seconds: 600\n  max_actions: 99"))


def test_unknown_key_is_rejected(tmp_path):
    for extra in ('dailycap: "1"\n', "allow_list: []\n", "debug: true\n"):
        with pytest.raises(ValueError):
            load(tmp_path, GOOD + extra)


@pytest.mark.parametrize("velocity", [
    "max_actions: 5.0\n  window_seconds: 600", "max_actions: 5.9\n  window_seconds: 600",
    "max_actions: true\n  window_seconds: 600", 'max_actions: "5"\n  window_seconds: 600',
    "max_actions: 0\n  window_seconds: 600", "max_actions: -1\n  window_seconds: 600",
    "max_actions: 1001\n  window_seconds: 600", "max_actions: 999999999\n  window_seconds: 600",
    "max_actions: 5\n  window_seconds: 0", "max_actions: 5\n  window_seconds: 86401",
    "max_actions: 5\n  window_seconds: true", "max_actions: 5",
    "window_seconds: 600", "max_actions: 5\n  window_seconds: 600\n  extra: 1", "max_actions: null\n  window_seconds: 600",
])
def test_bad_velocity_is_rejected(tmp_path, velocity):
    with pytest.raises(ValueError):
        load(tmp_path, GOOD.replace("max_actions: 5\n  window_seconds: 600", velocity))


def test_velocity_edges_are_accepted(tmp_path):
    r = load(tmp_path, GOOD.replace("max_actions: 5\n  window_seconds: 600", "max_actions: 1000\n  window_seconds: 86400"))
    assert (r["velocity_max_actions"], r["velocity_window_seconds"]) == (1000, 86400)
    r = load(tmp_path, GOOD.replace("max_actions: 5\n  window_seconds: 600", "max_actions: 1\n  window_seconds: 1"))
    assert (r["velocity_max_actions"], r["velocity_window_seconds"]) == (1, 1)


@pytest.mark.parametrize("velocity_block", ["velocity: 5", "velocity: [5, 600]", "velocity: null", "velocity: {}"])
def test_velocity_must_be_a_mapping_with_both_numbers(tmp_path, velocity_block):
    text = GOOD.replace("velocity:\n  max_actions: 5\n  window_seconds: 600", velocity_block)
    with pytest.raises(ValueError):
        load(tmp_path, text)


@pytest.mark.parametrize("origins", ["user_chat", "''", "[\"\"]", "[' user_chat']", "[user_chat, '']", "[1]", "[null]",
                                     "[true]", "[[user_chat]]", "{a: b}", "['a b']", "['" + "x" * 65 + "']", "['user\\nchat']"])
def test_bad_trusted_origins_are_rejected(tmp_path, origins):
    with pytest.raises(ValueError):
        load(tmp_path, GOOD.replace("[user_chat]", origins))


def test_trusted_origins_empty_or_blank_means_nobody_is_trusted(tmp_path):
    assert load(tmp_path, GOOD.replace("[user_chat]", "[]"))["trusted_origins"] == []
    assert load(tmp_path, GOOD.replace("trusted_origins: [user_chat]", "trusted_origins:"))["trusted_origins"] == []


@pytest.mark.parametrize("chain", ["0", "-1", "'31337'", "true", "1.5", "[1]", str(2 ** 64)])
def test_bad_chain_id_is_rejected(tmp_path, chain):
    with pytest.raises(ValueError):
        load(tmp_path, GOOD.replace("chain_id: null", f"chain_id: {chain}"))


def test_good_chain_id_is_accepted(tmp_path):
    assert load(tmp_path, GOOD.replace("chain_id: null", "chain_id: 31337"))["chain_id"] == 31337


@pytest.mark.parametrize("entry", ["0x123", ALICE[:-1], ALICE + "0", ALICE.replace("0x", "0X"), "70997970C51812dc3A010C7d01b50e0d17dc79C8",
                                   "0xZZ997970C51812dc3A010C7d01b50e0d17dc79C8", "", " " + ALICE, ALICE + " ", "0x" + "0" * 40, "0x" + "0" * 40 + "\n"])
def test_bad_allowlist_entries_are_rejected(tmp_path, entry):
    with pytest.raises(ValueError):
        load(tmp_path, GOOD.replace("allowlist: []", f"allowlist: [{json.dumps(entry)}]"))


@pytest.mark.parametrize("block", ["allowlist: user", "allowlist: 5", "allowlist: {a: b}", "allowlist: [5]", "allowlist: [null]"])
def test_allowlist_must_be_a_list_of_strings(tmp_path, block):
    with pytest.raises(ValueError):
        load(tmp_path, GOOD.replace("allowlist: []", block))


def test_good_allowlist_is_accepted_and_mixed_case_kept(tmp_path):
    assert load(tmp_path, GOOD.replace("allowlist: []", f'allowlist: ["{ALICE}"]'))["allowlist"] == [ALICE]


@pytest.mark.parametrize("content", [
    "", "   \n", "# only a comment\n", "[]", "[1, 2]", "just text", "42", "null", "~", "{}",
    "auto_limit: [", "a: b: c: d", "\t\tbad: indent", "key: *undefined_alias", "!!python/object/apply:os.getcwd []",
    "x: !!python/object/apply:os.system ['echo hi']", "--- \n--- \n", "\x00\x01\x02", "<<: {a: 1}",
])
def test_garbage_documents_are_rejected_with_valueerror_only(tmp_path, content):
    with pytest.raises(ValueError):
        load(tmp_path, content)


def test_missing_file_directory_and_binary_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        state.load_rules(tmp_path / "nope.yaml")
    with pytest.raises(ValueError):
        state.load_rules(tmp_path)                                    # a folder
    binary = tmp_path / "b.yaml"
    binary.write_bytes(b"\xff\xfe\x00bad bytes\x80\x81")
    with pytest.raises(ValueError):
        state.load_rules(binary)


def test_oversized_file_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        load(tmp_path, GOOD + "# " + "x" * state.MAX_RULES_BYTES + "\n")


def test_deeply_nested_and_alias_bomb_documents_are_rejected_quickly(tmp_path):
    with pytest.raises(ValueError):
        load(tmp_path, "a: " + "[" * 4000 + "]" * 4000 + "\n")
    bomb = "a: &a [x,x,x,x,x,x,x,x,x]\n" + "".join(
        f"{chr(98 + i)}: &{chr(98 + i)} [{','.join(['*' + chr(97 + i)] * 9)}]\n" for i in range(8))
    with pytest.raises(ValueError):
        load(tmp_path, bomb)


def test_loader_never_executes_anything(tmp_path):
    marker = tmp_path / "pwned"
    with pytest.raises(ValueError):
        load(tmp_path, f"x: !!python/object/apply:pathlib.Path.touch [{marker!r}]\n")
    assert not marker.exists()


def _invariants(r):
    assert set(r) == {"auto_limit", "max_tx", "daily_cap", "velocity_max_actions", "velocity_window_seconds",
                      "trusted_origins", "chain_id", "allowlist"}
    for k in ("auto_limit", "max_tx", "daily_cap"):
        assert type(r[k]) is Decimal and r[k].is_finite() and 0 <= r[k] <= state.MAX_LIMIT
    assert r["auto_limit"] <= r["max_tx"]
    assert type(r["velocity_max_actions"]) is int and 1 <= r["velocity_max_actions"] <= 1000
    assert type(r["velocity_window_seconds"]) is int and 1 <= r["velocity_window_seconds"] <= 86400
    assert all(isinstance(o, str) and o for o in r["trusted_origins"])
    assert r["chain_id"] is None or (type(r["chain_id"]) is int and r["chain_id"] > 0)
    assert all(isinstance(a, str) and len(a) == 42 and int(a, 16) != 0 for a in r["allowlist"])


def test_fuzz_the_loader_it_either_returns_a_valid_config_or_valueerror(tmp_path):
    rng = random.Random(1234)
    nasty = ["!!python/object:os.system", "&x", "*x", "<<:", "---", "\t", "\x00", "\u202e", "０", "٥", "1e999", "-1", "null", "true",
             "[", "]", "{", "}", "'", '"', ":", "- ", "#", "0x1F", ".inf", ".nan", "999999999999999999999999999999999", "\r", "\\"]
    path = tmp_path / "fuzz.yaml"
    accepted = rejected = 0
    for _ in range(1500):
        text = list(GOOD)
        for _ in range(rng.randint(1, 4)):
            pos = rng.randrange(len(text))
            op = rng.choice(["insert", "delete", "replace", "token"])
            if op == "insert":
                text.insert(pos, rng.choice("0123456789abc:- \n\"'[]{}"))
            elif op == "delete":
                del text[pos]
            elif op == "replace":
                text[pos] = rng.choice("0123456789xyz:\n\"' ")
            else:
                text.insert(pos, rng.choice(nasty))
        path.write_text("".join(text), encoding="utf-8")
        try:
            result = state.load_rules(path)
        except ValueError:
            rejected += 1
        else:
            _invariants(result)
            accepted += 1
    assert accepted > 0 and rejected > 100


# =====================================================================================================
# 2. amounts
# =====================================================================================================

@pytest.mark.parametrize("amount,w", [("1", 10 ** 18), (1, 10 ** 18), (Decimal("1.5"), 15 * 10 ** 17), ("0.5", 5 * 10 ** 17),
                                      ("0.000000000000000001", 1), (Decimal("1E-18"), 1),
                                      ("12345.6789012345678901234", 12345678901234567890124)])      # 19th decimal: rounded UP
def test_valid_amounts_become_exact_whole_units(amount, w):
    assert state._to_wei(amount) == w


@pytest.mark.parametrize("amount", ["0.0000000000000000001", "0.0000000000000000000000000000001", Decimal("1E-30"), "0.0000000000000000011"])
def test_tiny_amounts_round_up_never_down(amount):
    exact = Fraction(Decimal(amount))
    assert state._to_wei(amount) == ceil(exact * 10 ** 18) and state._to_wei(amount) >= 1


@pytest.mark.parametrize("amount", [0.1, 1.0, True, False, None, [], {}, (1,), b"5", object()])
def test_wrong_types_are_refused(amount):
    with pytest.raises(TypeError):
        state.record_spend(amount)


@pytest.mark.parametrize("amount", ["", " 5", "5 ", "-1", "-0.1", "-0", "+1", "1e3", "1E3", "NaN", "Infinity", "-Infinity", "abc", "1,000",
                                    "٥", "５", "0x10", "1" * 101, ".5", "5.", "1.2.3", "1000000000001", 10 ** 13, -1, -10 ** 30,
                                    Decimal("NaN"), Decimal("sNaN"), Decimal("Infinity"), Decimal("-Infinity"), Decimal("-0.1"), Decimal("1E+13")])
def test_bad_amounts_are_refused_and_change_nothing(amount):
    state.record_spend("5")
    with pytest.raises((TypeError, ValueError)):
        state.record_spend(amount)
    assert state.spent_last_24h() == Decimal(5)


def test_negative_spend_cannot_lower_the_total():
    state.record_spend("900")
    with pytest.raises(ValueError):
        state.record_spend("-900")
    assert state.spent_last_24h() == Decimal(900)


def test_nan_cannot_poison_the_memory():
    with pytest.raises(ValueError):
        state.record_spend("NaN")
    state.record_spend("3")
    assert state.spent_last_24h() == Decimal(3)


def test_zero_is_ignored_and_writes_nothing():
    state.record_spend("0")
    state.record_spend("0.000")
    state.record_spend(Decimal("-0"))
    assert not Path(os.environ["SPEND_LEDGER_PATH"]).exists() and state.spent_last_24h() == 0


def test_no_spend_is_zero():
    assert state.spent_last_24h() == Decimal(0)


def test_sums_are_exact_not_float():
    state.record_spend("0.1")
    state.record_spend("0.2")
    assert state.spent_last_24h() == Decimal("0.3")


def test_no_precision_is_lost_at_large_amounts():
    state.record_spend("1000000000000")
    for _ in range(10):
        state.record_spend("0.000000000000000001")
    assert state.spent_last_24h() == Decimal("1000000000000.00000000000000001")


def test_total_prints_cleanly():
    state.record_spend("900")
    assert str(state.spent_last_24h()) == "900"
    state.record_spend("0.5")
    assert str(state.spent_last_24h()) == "900.5"
    assert str(Decimal(state._wei_to_decimal(0))) == "0"


def test_decimal_input_from_the_policy_engine_works():
    state.record_spend(Decimal("10000000000000000000").scaleb(-18))        # exactly how policy.py calls it
    assert state.spent_last_24h() == Decimal(10)


# =====================================================================================================
# 3. the 24-hour window
# =====================================================================================================

def test_money_counts_until_exactly_24h_then_stops(clock):
    state.record_spend("100")
    clock.t += DAY
    assert state.spent_last_24h() == 100                  # exactly 24h old: still counted (cautious side)
    clock.t += 0.001
    assert state.spent_last_24h() == 0                    # a hair later: gone


def test_old_and_new_spend_are_separated(clock):
    state.record_spend("100")
    clock.t += DAY - 10
    state.record_spend("5")
    clock.t += 20
    assert state.spent_last_24h() == 5


def test_an_entry_from_the_future_is_still_counted(clock):
    state.record_spend("100")
    clock.t -= 3600                                       # the clock was set backwards
    assert state.spent_last_24h() == 100
    clock.t -= 10 * DAY
    assert state.spent_last_24h() == 100


def test_time_cannot_be_chosen_by_the_caller():
    for call in (lambda: state.record_spend("1", now=0), lambda: state.spent_last_24h(now=0),
                 lambda: state.record_action(now=0), lambda: state.actions_in_window(now=0)):
        with pytest.raises(TypeError):
            call()


def test_expired_entries_are_cleaned_out_of_the_file(clock):
    state.record_spend("1")
    state.record_spend("2")
    assert len(ledger_lines()) == 2
    clock.t += DAY + 1
    state.record_spend("4")
    assert len(ledger_lines()) == 1 and state.spent_last_24h() == 4


def test_many_entries_are_merged_cautiously_never_lost(clock, monkeypatch):
    monkeypatch.setattr(state, "MAX_LEDGER_ENTRIES", 5)
    exact = []
    for i in range(30):
        clock.t += 60
        state.record_spend("1")
        exact.append((clock.t, 1))
        assert len(ledger_lines()) <= 5
        for probe in (0, 3600, DAY - 100, DAY, DAY + 1000):
            now = clock.t
            clock.t = now + probe
            true_total = sum(a for ts, a in exact if clock.t - ts <= DAY)
            assert state.spent_last_24h() >= true_total        # merging may over-count, NEVER under-count
            clock.t = now
    assert state.spent_last_24h() == 30


def test_a_merged_entry_takes_the_newer_time_so_it_is_never_forgotten_early(clock, monkeypatch):
    monkeypatch.setattr(state, "MAX_LEDGER_ENTRIES", 1)      # every new spend forces a merge
    state.record_spend("1")                                   # at t0
    t0 = clock.t
    clock.t = t0 + 1000
    state.record_spend("2")                                   # merged with the first one
    clock.t = t0 + DAY + 500                                  # the first spend is expired, the second is not
    assert state.spent_last_24h() >= 2                        # an older merged time would wrongly give 0
    assert len(ledger_lines()) == 1


# =====================================================================================================
# 4. tamper-evident, durable ledger
# =====================================================================================================

def _ledger():
    return Path(os.environ["SPEND_LEDGER_PATH"])


def _three():
    for amount in ("10", "20", "30"):
        state.record_spend(amount)
    assert state.spent_last_24h() == 60


def test_ledger_lines_are_chained():
    _three()
    lines = [json.loads(l) for l in ledger_lines()]
    assert len(lines) == 3 and len({l["mac"] for l in lines}) == 3 and all(len(l["mac"]) == 64 for l in lines)


def test_editing_an_amount_is_detected():
    _three()
    lines = ledger_lines()
    entry = json.loads(lines[1])
    entry["wei"] = 1
    lines[1] = json.dumps(entry, separators=(",", ":")).encode()
    _ledger().write_bytes(b"\n".join(lines) + b"\n")
    for call in (state.spent_last_24h, lambda: state.record_spend("1")):
        with pytest.raises(state.StateCorruptError):
            call()


def test_deleting_a_middle_line_is_detected():
    _three()
    lines = ledger_lines()
    _ledger().write_bytes(lines[0] + b"\n" + lines[2] + b"\n")
    with pytest.raises(state.StateCorruptError):
        state.spent_last_24h()


def test_reordering_and_duplicating_lines_is_detected():
    _three()
    a, b, c = ledger_lines()
    for body in (b"\n".join([b, a, c]) + b"\n", b"\n".join([a, a, b, c]) + b"\n", b"\n".join([a, b, b, c]) + b"\n"):
        _ledger().write_bytes(body)
        with pytest.raises(state.StateCorruptError):
            state.spent_last_24h()


def test_forged_lines_are_detected():
    _three()
    forged = json.dumps({"ts": 1.0, "wei": 5, "mac": "0" * 64}, separators=(",", ":")).encode() + b"\n"
    _ledger().write_bytes(_ledger().read_bytes() + forged)
    with pytest.raises(state.StateCorruptError):
        state.spent_last_24h()


@pytest.mark.parametrize("junk", [b"{", b"\n", b"not json\n", b"[]\n", b"null\n", b"123\n", b'{"ts":1,"wei":1}\n',
                                  b'{"ts":1,"wei":1,"mac":"x","extra":1}\n', b"\xff\xfe\n", b'{"ts":NaN,"wei":1,"mac":"' + b"0" * 64 + b'"}\n',
                                  b'{"ts":1,"wei":-5,"mac":"' + b"0" * 64 + b'"}\n', b'{"ts":true,"wei":1,"mac":"' + b"0" * 64 + b'"}\n',
                                  b'{"ts":1,"wei":1.5,"mac":"' + b"0" * 64 + b'"}\n', b'{"ts":1,"wei":true,"mac":"' + b"0" * 64 + b'"}\n'])
def test_garbage_in_the_ledger_is_detected(junk):
    _ledger().write_bytes(junk)
    with pytest.raises(state.StateCorruptError):
        state.spent_last_24h()
    with pytest.raises(state.StateCorruptError):
        state.record_spend("1")


def test_a_half_written_last_line_is_detected():
    _three()
    _ledger().write_bytes(_ledger().read_bytes()[:-20])
    with pytest.raises(state.StateCorruptError):
        state.spent_last_24h()


def test_a_blank_line_in_the_middle_is_detected():
    _three()
    a, b, c = ledger_lines()
    _ledger().write_bytes(a + b"\n\n" + b + b"\n" + c + b"\n")
    with pytest.raises(state.StateCorruptError):
        state.spent_last_24h()


def test_ledger_made_with_another_secret_is_rejected(monkeypatch):
    _three()
    monkeypatch.setenv("APPROVAL_SECRET", "a-completely-different-secret-9876543210")
    with pytest.raises(state.StateCorruptError):
        state.spent_last_24h()


@pytest.mark.parametrize("secret", ["", "short"])
def test_without_a_proper_secret_the_memory_refuses(monkeypatch, secret):
    monkeypatch.setenv("APPROVAL_SECRET", secret)
    with pytest.raises(state.StateError):
        state.record_spend("1")
    with pytest.raises(state.StateError):
        state.spent_last_24h()
    monkeypatch.delenv("APPROVAL_SECRET")
    with pytest.raises(state.StateError):
        state.spent_last_24h()


def test_a_folder_in_place_of_the_ledger_is_an_error_not_zero():
    _ledger().mkdir()
    with pytest.raises(state.StateError):
        state.spent_last_24h()


def test_a_failed_write_never_corrupts_the_memory(monkeypatch):
    state.record_spend("5")
    with monkeypatch.context() as m:
        m.setattr(state.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("disk full")))
        with pytest.raises(OSError):
            state.record_spend("7")
    # the line may or may not have reached the disk; either way the memory is still intact and verifiable
    assert state.spent_last_24h() in (Decimal(5), Decimal(12))


def test_a_failed_compaction_leaves_the_old_ledger_intact(clock, monkeypatch):
    state.record_spend("5")
    clock.t += DAY + 1
    before = _ledger().read_bytes()
    monkeypatch.setattr(state.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("nope")))
    with pytest.raises(OSError):
        state.record_spend("7")
    assert _ledger().read_bytes() == before
    assert not [p for p in _ledger().parent.iterdir() if p.name.endswith(".tmp")]      # no litter


def test_ledger_directory_is_created_if_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("SPEND_LEDGER_PATH", str(tmp_path / "deep" / "er" / "ledger.jsonl"))
    state.record_spend("2")
    assert state.spent_last_24h() == 2


# ---- restarts: a brand-new Python process must see the same memory -------------------------------

def _other_process(code):
    result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=os.environ.copy(), capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_spending_survives_a_restart():
    state.record_spend("123.25")
    assert _other_process("from firewall import state; print(state.spent_last_24h())") == "123.25"


def test_spending_by_another_process_is_seen_and_chains_continue():
    state.record_spend("1")
    _other_process("from firewall import state; state.record_spend('2')")
    state.record_spend("4")
    assert state.spent_last_24h() == 7


def test_kill_switch_survives_a_restart():
    state.set_kill_switch(True)
    assert _other_process("from firewall import state; print(state.kill_switch_on())") == "True"
    state.set_kill_switch(False)
    assert _other_process("from firewall import state; print(state.kill_switch_on())") == "False"


def test_velocity_is_kept_in_a_file_so_a_restart_does_not_forget_it():
    """(Changed on purpose: velocity used to be in memory only, so a restart handed out a fresh budget.)"""
    state.record_action()
    assert _other_process("from firewall import state; print(state.actions_in_window(600))") == "1"


# =====================================================================================================
# 5. velocity
# =====================================================================================================

def test_velocity_counts_only_inside_the_window(clock):
    for _ in range(3):
        state.record_action()
        clock.t += 100
    assert state.actions_in_window(600) == 3
    clock.t += 350                                        # the first action is now 650s old
    assert state.actions_in_window(600) == 2


def test_velocity_window_boundary_is_cautious(clock):
    state.record_action()
    clock.t += 600
    assert state.actions_in_window(600) == 1
    clock.t += 0.001
    assert state.actions_in_window(600) == 0


def test_velocity_entries_from_the_future_are_still_counted(clock):
    state.record_action()
    clock.t -= 7200                                       # the clock was set backwards
    assert state.actions_in_window(600) == 1


def test_velocity_uses_rules_window_by_default(clock):
    state.record_action()
    clock.t += 599
    assert state.actions_in_window() == 1
    clock.t += 2
    assert state.actions_in_window() == 0


@pytest.mark.parametrize("window", [0, -1, 1.5, True, "600", "abc", [], 86401, 10 ** 12])
def test_bad_windows_are_refused(window):
    with pytest.raises(ValueError):
        state.actions_in_window(window)


def test_action_memory_is_bounded_and_never_under_reports(monkeypatch):
    """The memory mirror AND the file keep only the newest ACTION_MEMORY actions (a small bound here: every record
    now reads the file, so a 10,000-iteration loop would be pointlessly slow)."""
    assert state.ACTION_MEMORY > state.MAX_VELOCITY_ACTIONS            # the real constant: always enough for any threshold
    monkeypatch.setattr(state, "ACTION_MEMORY", 50)
    monkeypatch.setattr(state, "_ACTIONS", deque(maxlen=50))
    for _ in range(300):
        state.record_action()
    assert len(state._ACTIONS) == 50
    assert state.actions_in_window(600) == 50              # still far above any threshold up to 50
    assert len(state._velocity_path().read_text().splitlines()) == 50


def test_real_memory_bound_is_enforced(monkeypatch):
    monkeypatch.setattr(state, "ACTION_MEMORY", 200)
    monkeypatch.setattr(state, "_ACTIONS", deque(maxlen=200))
    for _ in range(200 + 100):
        state.record_action()
    assert len(state._ACTIONS) == 200 and state.actions_in_window(600) == 200


# =====================================================================================================
# 6. kill switch
# =====================================================================================================

def _flag():
    return Path(os.environ["KILL_SWITCH_PATH"])


def test_kill_switch_starts_off_and_toggles():
    assert state.kill_switch_on() is False
    state.set_kill_switch(True)
    assert state.kill_switch_on() is True and _flag().exists()
    state.set_kill_switch(False)
    assert state.kill_switch_on() is False and not _flag().exists()


def test_kill_switch_always_returns_a_real_bool():
    assert type(state.kill_switch_on()) is bool
    state.set_kill_switch(True)
    assert type(state.kill_switch_on()) is bool


def test_kill_switch_is_idempotent():
    state.set_kill_switch(True)
    state.set_kill_switch(True)
    assert state.kill_switch_on() is True
    state.set_kill_switch(False)
    state.set_kill_switch(False)
    assert state.kill_switch_on() is False


@pytest.mark.parametrize("value", [True, None, 0, 1, "", "false", "False", "off", "no", "0", [], [0], object(), 0.0, "True"])
def test_only_the_real_False_turns_the_kill_switch_off(value):
    state.set_kill_switch(value)
    assert state.kill_switch_on() is True                  # ambiguous input freezes the wallet
    state.set_kill_switch(False)
    assert state.kill_switch_on() is False


def test_a_leftover_flag_file_means_frozen_even_if_memory_says_off():
    _flag().write_text("ON\n")
    assert state.kill_switch_on() is True


def test_if_the_flag_cannot_be_checked_it_counts_as_on(monkeypatch):
    monkeypatch.setattr(state, "_flag_path", lambda: (_ for _ in ()).throw(OSError("boom")))
    assert state.kill_switch_on() is True


def test_if_the_flag_cannot_be_removed_the_wallet_stays_frozen(monkeypatch):
    state.set_kill_switch(True)
    monkeypatch.setattr(Path, "unlink", lambda self, missing_ok=False: (_ for _ in ()).throw(PermissionError("locked")))
    with pytest.raises(state.StateError):
        state.set_kill_switch(False)
    assert state.kill_switch_on() is True


def test_if_the_flag_cannot_be_saved_the_wallet_is_still_frozen_now(monkeypatch):
    monkeypatch.setattr(Path, "write_text", lambda self, *a, **k: (_ for _ in ()).throw(OSError("read-only disk")))
    with pytest.raises(state.StateError):
        state.set_kill_switch(True)
    assert state.kill_switch_on() is True                   # frozen in memory even though it could not be saved


def test_a_folder_in_place_of_the_flag_cannot_be_cleared():
    _flag().mkdir()
    assert state.kill_switch_on() is True
    with pytest.raises(state.StateError):
        state.set_kill_switch(False)
    assert state.kill_switch_on() is True


# =====================================================================================================
# 7. concurrency
# =====================================================================================================

def _run_threads(fn, n):
    errors = []

    def wrapper(i):
        try:
            fn(i)
        except Exception as exc:                       # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=wrapper, args=(i,)) for i in range(n)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors, errors


def test_parallel_spends_are_all_counted_and_the_chain_stays_valid():
    _run_threads(lambda i: [state.record_spend("0.000000000000000001") for _ in range(25)], 8)
    assert state.spent_last_24h() == Decimal(200) / Decimal(10 ** 18)
    assert len(ledger_lines()) == 200


def test_reading_while_writing_never_fails():
    seen = []
    _run_threads(lambda i: [state.record_spend("1") if i % 2 else seen.append(state.spent_last_24h()) for _ in range(20)], 8)
    assert state.spent_last_24h() == 80 and all(0 <= s <= 80 for s in seen)


def test_parallel_actions_are_all_counted():
    _run_threads(lambda i: [state.record_action() for _ in range(100)], 10)
    assert state.actions_in_window(600) == 1000


def test_parallel_kill_switch_flips_end_in_a_consistent_state():
    _run_threads(lambda i: state.set_kill_switch(i % 2 == 0), 20)        # even i -> True (on), odd i -> False (off)
    assert type(state.kill_switch_on()) is bool
    state.set_kill_switch(False)
    assert state.kill_switch_on() is False


# =====================================================================================================
# 8. model-based (differential) test: the real thing must always agree with a tiny, obviously-correct model
# =====================================================================================================

def test_model_based_random_operations_agree_with_a_simple_reference(clock):
    rng = random.Random(20261016)
    model = []                                              # [(time, exact Fraction amount rounded up to wei)]
    amounts = ["0", "1", "0.1", "0.000000000000000001", "7.123456789012345678", "0.0000000000000000005", "49.99", "500", "0.3333333333333333339"]
    for step in range(400):
        op = rng.choice(["spend", "spend", "advance", "advance", "check"])
        if op == "spend":
            amount = rng.choice(amounts)
            state.record_spend(amount)
            w = ceil(Fraction(Decimal(amount)) * 10 ** 18)
            if w:
                model.append((clock.t, w))
        elif op == "advance":
            clock.t += rng.choice([1, 60, 3600, DAY / 2, DAY - 1, DAY, DAY + 1, 5 * DAY])
        else:
            expected = sum(w for ts, w in model if clock.t - ts <= DAY)
            assert state.spent_last_24h() == state._wei_to_decimal(expected), f"step {step}"
    expected = sum(w for ts, w in model if clock.t - ts <= DAY)
    assert state.spent_last_24h() == state._wei_to_decimal(expected)


# =====================================================================================================
# 9. hygiene
# =====================================================================================================

def test_reset_is_for_tests_only(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST")
    with pytest.raises(RuntimeError):
        state.reset()


def test_reset_refuses_to_touch_real_files(monkeypatch):
    monkeypatch.delenv("SPEND_LEDGER_PATH")
    with pytest.raises(RuntimeError):
        state.reset()


def test_reset_really_forgets_everything():
    state.record_spend("5")
    state.record_action()
    state.set_kill_switch(True)
    state.reset()
    assert state.spent_last_24h() == 0 and state.actions_in_window(600) == 0 and state.kill_switch_on() is False


def test_set_kill_switch_keeps_its_signature():
    import inspect
    assert list(inspect.signature(state.set_kill_switch).parameters) == ["on"]
    assert list(inspect.signature(state.kill_switch_on).parameters) == []