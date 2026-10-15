"""Tests for firewall/policy.py (issue #15): every rule, precedence, plain-English reasons, tokens."""
from decimal import Decimal

import pytest

import threading
import time

from firewall import audit, policy, state, tokens
from shared.types import ActionRequest, SimResult, TxPlan
from wallet_engine.binding import token_binding

TOKEN = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"          # on the allowlist
CAROL = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"          # on the allowlist (a spender)
BOB = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"            # NOT on the allowlist
FAKE_ALICE = "0x7099" + "ab" * 16 + "79C8"                   # same first 4 / last 4 digits as ALICE
CHAIN = 31337
UNIT = 10 ** 18

RULES = f"""
auto_limit: "50"
max_tx: "500"
daily_cap: "1000"
velocity:
  max_actions: 5
  window_seconds: 600
trusted_origins: [user_chat]
chain_id: {CHAIN}
allowlist: ["{ALICE}", "{CAROL}"]
"""


@pytest.fixture(autouse=True)
def setup(monkeypatch, tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(RULES)
    monkeypatch.setenv("RULES_PATH", str(rules))
    monkeypatch.setenv("APPROVAL_SECRET", "unit-test-secret-0123456789abcdef")
    monkeypatch.setenv("TOKEN_ADDRESS", TOKEN)
    # (tests/conftest.py also clears spend, tokens and open questions before every test)


# ---------- helpers: build a request, the plan the engine would build, and a passing simulation
def _word(value):
    return format(value, "064x")


def _calldata(selector, address, raw):
    return "0x" + selector + _word(int(address, 16)) + _word(raw)


def make(action="transfer", to=ALICE, amount="10", unlimited=False, origin="user_chat", rid="r1",
         chain_id=CHAIN, raw=None, data_to=None, token=TOKEN):
    """Return (req, plan, sim). raw / data_to let a test make the calldata differ from the request."""
    if raw is None:
        raw = 2 ** 256 - 1 if unlimited else int(Decimal(amount) * UNIT)
    if action == "revoke":
        raw = 0
    selector = "a9059cbb" if action == "transfer" else "095ea7b3"
    plan = TxPlan(chain_id=chain_id, from_addr="0x" + "11" * 20, to=token, value=0,
                  data=_calldata(selector, data_to or to, raw), gas=60000,
                  function="x", args={}, summary="test")
    req = ActionRequest(rid, action, token, to, "0" if action == "revoke" else amount, unlimited, origin)
    out = str(Decimal(raw) / UNIT) if action == "transfer" else "0"
    sim = SimResult(ok=True, revert_reason=None, outflow=out, allowance_after=None)
    return req, plan, sim


def run(**kw):
    req, plan, sim = make(**kw)
    return policy.evaluate(req, plan, sim)


# ---------- ALLOW
def test_small_transfer_to_allowlisted_address_is_allowed():
    d = run(amount="10")
    assert d.decision == "allow" and d.rule_ids == ["ALLOW"] and d.approval_token


def test_exactly_the_auto_limit_is_allowed():
    assert run(amount="50").decision == "allow"


def test_allow_token_matches_exactly_this_transaction():
    req, plan, sim = make(amount="10")
    d = policy.evaluate(req, plan, sim)
    b = token_binding(plan)
    assert tokens.verify_token(d.approval_token, "r1", b["action"], b["token"], b["to"], b["amount"])
    assert not tokens.verify_token(d.approval_token, "r1", b["action"], b["token"], _norm_bob(), b["amount"])


def _norm_bob():
    return BOB.lower()


def test_revoke_is_allowed_and_gets_a_token():
    d = run(action="revoke", to=BOB)
    assert d.decision == "allow" and d.approval_token


def test_approve_small_amount_to_allowlisted_spender_is_allowed():
    assert run(action="approve", to=CAROL, amount="20").decision == "allow"


# ---------- DENY rules
def test_prv01_untrusted_origin_is_denied_with_no_token():
    for origin in ("public_feed", "nft_metadata", "tool_output"):
        d = run(origin=origin)
        assert d.decision == "deny" and "PRV-01" in d.rule_ids and d.approval_token is None


def test_kil01_kill_switch_denies_everything():
    state.set_kill_switch(True)
    d = run(amount="1")
    assert d.decision == "deny" and "KIL-01" in d.rule_ids and d.approval_token is None


def test_net01_wrong_chain_id_is_denied():
    d = run(chain_id=1)
    assert d.decision == "deny" and "NET-01" in d.rule_ids


def test_net01_unknown_expected_chain_is_denied(monkeypatch, tmp_path):
    rules = tmp_path / "r2.yaml"
    rules.write_text(RULES.replace(f"chain_id: {CHAIN}", "chain_id: null"))
    monkeypatch.setenv("RULES_PATH", str(rules))
    monkeypatch.setattr(policy, "_node_chain_id", lambda: None)
    assert "NET-01" in run().rule_ids


def test_net01_null_chain_id_uses_the_node(monkeypatch, tmp_path):
    rules = tmp_path / "r2.yaml"
    rules.write_text(RULES.replace(f"chain_id: {CHAIN}", "chain_id: null"))
    monkeypatch.setenv("RULES_PATH", str(rules))
    monkeypatch.setattr(policy, "_node_chain_id", lambda: CHAIN)
    assert run().decision == "allow"


def test_apr01_unlimited_approval_is_denied():
    d = run(action="approve", to=CAROL, unlimited=True, amount="0")
    assert d.decision == "deny" and "APR-01" in d.rule_ids


def test_apr02_approval_to_unknown_spender_is_denied():
    d = run(action="approve", to=BOB, amount="5")
    assert d.decision == "deny" and "APR-02" in d.rule_ids


def test_adr01_lookalike_recipient_is_denied():
    d = run(to=FAKE_ALICE)
    assert d.decision == "deny" and "ADR-01" in d.rule_ids
    assert "ALW-01" not in d.rule_ids          # a look-alike is a scam, not just "new"


def test_adr01_lookalike_spender_is_denied():
    assert "ADR-01" in run(action="approve", to=FAKE_ALICE, amount="5").rule_ids


def test_sim01_failed_simulation_is_denied():
    req, plan, _ = make()
    d = policy.evaluate(req, plan, SimResult(False, "TestUSD: insufficient balance", "0", None))
    assert d.decision == "deny" and "SIM-01" in d.rule_ids and "insufficient balance" in d.reasons[0]


def test_sim01_missing_simulation_is_denied():
    req, plan, _ = make()
    assert "SIM-01" in policy.evaluate(req, plan, None).rule_ids


def test_sim01_outflow_bigger_than_requested_is_denied():
    req, plan, _ = make(amount="10")
    d = policy.evaluate(req, plan, SimResult(True, None, "11", None))
    assert d.decision == "deny" and "SIM-01" in d.rule_ids


def test_sim01_calldata_recipient_differs_from_request_is_denied():
    d = run(to=ALICE, data_to=BOB)
    assert d.decision == "deny" and "SIM-01" in d.rule_ids


def test_sim01_calldata_amount_differs_from_request_is_denied():
    d = run(amount="10", raw=400 * UNIT)
    assert d.decision == "deny" and "SIM-01" in d.rule_ids


def test_sim01_garbage_calldata_is_denied():
    req, plan, sim = make()
    plan.data = "0xdeadbeef"
    assert "SIM-01" in policy.evaluate(req, plan, sim).rule_ids


def test_lim01_over_max_per_tx_is_denied():
    d = run(amount="501")
    assert d.decision == "deny" and "LIM-01" in d.rule_ids


def test_exactly_max_tx_is_not_lim01():
    assert "LIM-01" not in run(amount="500").rule_ids


def test_lim03_daily_cap_is_denied():
    state.record_spend("900")
    d = run(amount="150")
    assert d.decision == "deny" and "LIM-03" in d.rule_ids


def test_lim03_exactly_reaching_the_cap_is_ok():
    state.record_spend("950")
    assert "LIM-03" not in run(amount="50").rule_ids


# ---------- ASK rules
def test_alw01_new_recipient_asks():
    d = run(to=BOB, amount="10")
    assert d.decision == "ask" and d.rule_ids == ["ALW-01"] and d.approval_token is None


def test_lim02_over_auto_limit_asks():
    d = run(amount="51")
    assert d.decision == "ask" and d.rule_ids == ["LIM-02"]


def test_vel01_sixth_action_in_window_asks():
    for i in range(5):
        assert run(rid=f"r{i}", amount="1").decision == "allow"
    d = run(rid="r6", amount="1")
    assert d.decision == "ask" and d.rule_ids == ["VEL-01"]


# ---------- precedence
def test_deny_beats_ask():
    d = run(to=BOB, amount="501")      # new recipient (ask) + over max (deny)
    assert d.decision == "deny" and {"ALW-01", "LIM-01"} <= set(d.rule_ids)


def test_untrusted_origin_beats_everything_else_that_would_allow():
    assert run(origin="nft_metadata", amount="1").decision == "deny"


def test_several_asks_are_all_listed():
    d = run(to=BOB, amount="60")
    assert d.decision == "ask" and set(d.rule_ids) == {"ALW-01", "LIM-02"}


# ---------- reasons, defaults, never crashes
def test_reasons_are_plain_english_and_match_the_rule_ids():
    d = run(to=BOB, amount="60")
    assert len(d.reasons) == len(d.rule_ids) == 2
    assert all(isinstance(r, str) and len(r) > 20 for r in d.reasons)


def test_no_plan_is_denied_by_default():
    req, _, sim = make()
    d = policy.evaluate(req, None, sim)
    assert d.decision == "deny" and "DEF-01" in d.rule_ids


def test_a_crash_inside_the_rules_becomes_deny(monkeypatch):
    monkeypatch.setattr(policy, "_check_amount", lambda *a, **k: 1 / 0)
    d = run()
    assert d.decision == "deny" and d.rule_ids == ["DEF-01"] and d.approval_token is None


def test_missing_approval_secret_becomes_deny(monkeypatch):
    monkeypatch.delenv("APPROVAL_SECRET")
    d = run()
    assert d.decision == "deny" and d.approval_token is None


def test_decision_keeps_the_request_id():
    assert run(rid="abc-123").request_id == "abc-123"


# ---------- state side effects
def test_allowed_transfer_counts_toward_the_daily_spend():
    run(amount="20")
    assert state.spent_last_24h() == Decimal("20")


def test_denied_and_ask_do_not_count_as_spend():
    run(amount="501")
    run(to=BOB, amount="10")
    assert state.spent_last_24h() == Decimal(0)


# ---------- confirm()
def _ask_then_confirm(**kw):
    req, plan, sim = make(**kw)
    assert policy.evaluate(req, plan, sim).decision == "ask"
    return req, plan


def test_confirm_issues_a_token_after_an_ask():
    req, plan = _ask_then_confirm(to=BOB, amount="10")
    d = policy.confirm(req, plan)
    b = token_binding(plan)
    assert d.decision == "allow" and tokens.verify_token(d.approval_token, "r1", b["action"], b["token"], b["to"], b["amount"])


def test_confirm_without_any_question_is_denied_cnf01():
    req, plan, _ = make(to=BOB, amount="10")           # never went through evaluate()
    d = policy.confirm(req, plan)
    assert d.decision == "deny" and "CNF-01" in d.rule_ids and d.approval_token is None


def test_confirm_cannot_be_used_after_an_allow_or_deny():
    req, plan, sim = make(amount="10")
    assert policy.evaluate(req, plan, sim).decision == "allow"
    assert policy.confirm(req, plan).decision == "deny"
    req2, plan2, sim2 = make(amount="501", rid="r2")
    assert policy.evaluate(req2, plan2, sim2).decision == "deny"
    assert policy.confirm(req2, plan2).decision == "deny"


def test_a_question_can_be_confirmed_only_once():
    req, plan = _ask_then_confirm(to=BOB, amount="10")
    assert policy.confirm(req, plan).decision == "allow"
    again = policy.confirm(req, plan)
    assert again.decision == "deny" and "CNF-01" in again.rule_ids


def test_confirm_for_a_different_transaction_than_asked_is_denied():
    req, plan = _ask_then_confirm(to=BOB, amount="10")
    other_req, other_plan, _ = make(to=CAROL, amount="10")     # same request_id, other recipient
    assert policy.confirm(other_req, other_plan).decision == "deny"
    swapped_req, swapped_plan, _ = make(to=BOB, amount="10", data_to=ALICE)   # calldata swapped
    assert policy.confirm(swapped_req, swapped_plan).decision == "deny"
    assert policy.confirm(req, plan).decision == "allow"       # the real question is still open


def test_an_old_question_expires(monkeypatch):
    req, plan = _ask_then_confirm(to=BOB, amount="10")
    real = time.time()
    monkeypatch.setattr(policy.time, "time", lambda: real + policy.CONFIRM_WINDOW_SECONDS + 1)
    d = policy.confirm(req, plan)
    assert d.decision == "deny" and "CNF-01" in d.rule_ids


def test_confirm_does_not_override_a_hard_deny():
    req, plan, sim = make(to=BOB, amount="10")
    assert policy.evaluate(req, plan, sim).decision == "ask"
    state.set_kill_switch(True)                                  # something changed after the question
    assert policy.confirm(req, plan).decision == "deny"
    state.set_kill_switch(False)
    state.record_spend("995")                                    # daily cap now would be passed
    assert "LIM-03" in policy.confirm(req, plan).rule_ids


def test_confirm_refuses_untrusted_origin():
    req, plan, sim = make(to=BOB, amount="10", origin="public_feed")
    policy.evaluate(req, plan, sim)
    assert policy.confirm(req, plan).decision == "deny"


def test_confirm_with_no_plan_or_junk_is_denied():
    req, plan = _ask_then_confirm(to=BOB, amount="10")
    assert policy.confirm(req, None).decision == "deny"
    assert policy.confirm(None, plan).decision == "deny"


def test_confirmed_token_counts_toward_the_daily_spend():
    req, plan = _ask_then_confirm(to=BOB, amount="30")
    policy.confirm(req, plan)
    assert state.spent_last_24h() == Decimal("30")


# ---------- audit
def test_every_decision_is_written_to_the_audit_log():
    run(amount="10")
    run(origin="public_feed")
    entries = audit.tail(10)
    assert [e["event"]["decision"] for e in entries] == ["allow", "deny"]
    assert audit.check().ok
    assert "approval_token" not in str(entries)


# ---------- hardening: token contract, exact amounts, approvals, look-alikes, odd input
OTHER_TOKEN = "0xdAC17F958D2ee523a2206206994597C13D831ec7"


def test_tok01_other_token_contract_is_denied():
    d = run(token=OTHER_TOKEN)
    assert d.decision == "deny" and "TOK-01" in d.rule_ids and d.approval_token is None


def test_tok01_no_configured_token_means_deny(monkeypatch):
    monkeypatch.delenv("TOKEN_ADDRESS")
    assert "TOK-01" in run().rule_ids


def test_tok01_token_address_case_does_not_matter(monkeypatch):
    monkeypatch.setenv("TOKEN_ADDRESS", TOKEN.lower())
    assert run().decision == "allow"


def test_one_wei_difference_between_request_and_calldata_is_denied():
    req, plan, _ = make(amount="10", raw=10 * UNIT + 1)
    lying_sim = SimResult(True, None, "10", None)          # even if the dry run says exactly 10
    d = policy.evaluate(req, plan, lying_sim)
    assert d.decision == "deny" and "SIM-01" in d.rule_ids


@pytest.mark.parametrize("amount", ["NaN", "Infinity", "-5", "abc", "", "1e999999999", "0.0000000000000000001"])
def test_odd_amount_text_is_denied_and_never_crashes(amount):
    req, plan, sim = make(amount="10")
    req.amount = amount
    d = policy.evaluate(req, plan, sim)
    assert d.decision == "deny" and d.approval_token is None


def test_native_coin_attached_to_the_plan_is_denied():
    req, plan, sim = make()
    plan.value = 1
    assert "SIM-01" in policy.evaluate(req, plan, sim).rule_ids


def test_approval_that_reports_tokens_leaving_is_denied():
    req, plan, _ = make(action="approve", to=CAROL, amount="5")
    d = policy.evaluate(req, plan, SimResult(True, None, "5", "5"))
    assert d.decision == "deny" and "SIM-01" in d.rule_ids


def test_approvals_count_toward_the_daily_cap_check():
    state.record_spend("900")
    d = run(action="approve", to=CAROL, amount="150")
    assert d.decision == "deny" and "LIM-03" in d.rule_ids


def test_an_allowed_approval_is_remembered_as_potential_spend():
    run(action="approve", to=CAROL, amount="40")
    assert state.spent_last_24h() == Decimal("40")


def test_revoke_does_not_count_as_spend():
    run(action="revoke", to=CAROL)
    assert state.spent_last_24h() == Decimal(0)


def test_adr01_look_alike_helper_directly():
    allowed = {ALICE.lower()}
    a = ALICE.lower()
    assert policy._looks_like("0x" + a[2:6] + "0" * 32 + a[-4:], allowed)          # 4 + 4
    assert policy._looks_like("0x" + a[2:4] + "0" * 34 + a[-4:], allowed)          # 2 + 4
    assert policy._looks_like("0x" + a[2:8] + "0" * 32 + a[-2:], allowed)          # 6 + 2
    assert policy._looks_like("0x" + "0" * 34 + a[-6:], allowed)                   # 0 + 6
    assert policy._looks_like(a, allowed) is None                                  # the real one is not a look-alike
    assert policy._looks_like(BOB, allowed) is None                                # an unrelated address is not


def test_broken_rules_file_means_deny(monkeypatch, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("auto_limit: lots\n")
    monkeypatch.setenv("RULES_PATH", str(bad))
    d = run()
    assert d.decision == "deny" and d.approval_token is None


def test_non_request_input_is_denied_not_a_crash():
    for junk in (None, "send money", {"action": "transfer"}):
        d = policy.evaluate(junk, None, None)
        assert d.decision == "deny" and d.approval_token is None


def test_unlimited_flag_must_be_a_real_true():
    req, plan, sim = make(action="approve", to=CAROL, unlimited=True, amount="0")
    req.unlimited = "yes"
    assert policy.evaluate(req, plan, sim).decision == "deny"


# ---------- hardening: audit, locking
def test_if_the_audit_log_cannot_be_written_nothing_is_allowed(monkeypatch):
    def broken(event):
        raise OSError("disk full")
    monkeypatch.setattr(policy.audit, "log", broken)
    d = run(amount="10")
    assert d.decision == "deny" and d.approval_token is None and "DEF-01" in d.rule_ids
    assert state.spent_last_24h() == Decimal(0)


def test_deny_and_ask_still_work_when_the_audit_log_is_broken(monkeypatch):
    monkeypatch.setattr(policy.audit, "log", lambda event: (_ for _ in ()).throw(OSError("disk full")))
    assert run(amount="501").decision == "deny"
    assert run(to=BOB, amount="10", rid="r2").decision == "ask"


def test_parallel_requests_cannot_slip_past_the_daily_cap(monkeypatch, tmp_path):
    rules = tmp_path / "busy.yaml"
    rules.write_text(RULES.replace("auto_limit: \"50\"", "auto_limit: \"500\"").replace("max_actions: 5", "max_actions: 1000"))
    monkeypatch.setenv("RULES_PATH", str(rules))
    results = []

    def work(i):
        results.append(run(rid=f"p{i}", amount="100").decision)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("allow") == 10                      # 10 x 100 = the 1000 cap, never more
    assert state.spent_last_24h() == Decimal("1000")