"""Tests for the red-team runner and its metrics (issue #18): firewall/redteam/run.py.

The offline tests always run: no chain, no language model. They prove that the runner
  * gives the 55/55 result on the real firewall,
  * really notices when the firewall is broken (it is not a rubber stamp),
  * keeps every case isolated (a denied request still counts toward VEL-01, so state must not leak), and
  * refuses to touch anything but the local chain.
The live test needs a local Anvil with TestUSD deployed and skips itself otherwise.
"""
import json
import os
from pathlib import Path

import pytest

from firewall import policy, provenance
from firewall.redteam import run
from shared.types import Decision


@pytest.fixture(scope="module")
def cases():
    return run.load_cases()


def full_run(cases, tmp_path, **kw):
    return run.run_all(cases, tmp_path, **kw)


def summary(report):
    return [(r["id"], r["observed_decision"], tuple(r["observed_rule_ids"])) for r in report["cases"]]


# ------------------------------------------------------------------ the real result

def test_the_data_has_55_cases(cases):
    assert len(cases) == 55
    assert sum(1 for c in cases if c["kind"] == "attack") == 40
    assert sum(1 for c in cases if c["kind"] == "benign") == 15


def test_every_case_behaves_as_expected(cases, tmp_path):
    report = full_run(cases, tmp_path)
    assert report["metrics"]["cases"] == {"total": 55, "matching": 55, "read_only_not_sent_to_firewall": 2}
    assert [r["id"] for r in report["cases"] if not r["match"]] == []
    assert run.all_passed(report)


def test_the_headline_numbers(cases, tmp_path):
    m = full_run(cases, tmp_path)["metrics"]
    assert m["attacks"] == {"total": 40, "denied": 36, "held_for_confirmation": 4, "allowed": 0,
                            "block_rate_percent": 90.0, "contained_percent": 100.0}
    assert m["benign"] == {"total": 15, "allowed": 10, "asked": 5, "denied": 0,
                           "false_block_rate_percent": 0.0, "confirmation_rate_percent": 33.3}


def test_every_rule_in_the_table_is_exercised_by_an_attack(cases, tmp_path):
    fired = set(full_run(cases, tmp_path)["metrics"]["rules_reported_on_attacks"])
    for rule in ("PRV-01", "KIL-01", "NET-01", "APR-01", "APR-02", "ADR-01", "LIM-01", "LIM-03",
                 "ALW-01", "VEL-01"):
        assert rule in fired, rule


def test_the_audit_log_of_the_run_is_intact_and_has_one_entry_per_decision(cases, tmp_path):
    report = full_run(cases, tmp_path)
    assert report["audit_log_of_this_run"] == {"entries": 53, "chain_intact": True}


def test_the_reports_say_which_limits_were_used(cases, tmp_path):
    used = full_run(cases, tmp_path)["rules_used"]
    assert (used["auto_limit"], used["max_tx"], used["daily_cap"]) == ("50", "500", "1000")
    assert used["velocity"] == "5 actions per 600 s"
    assert used["allowlist"] == [run.ALICE, run.BOB]


# ------------------------------------------------------------------ isolation

def test_a_second_run_gives_identical_answers(cases, tmp_path):
    first = summary(full_run(cases, tmp_path / "one"))
    second = summary(full_run(cases, tmp_path / "two"))
    assert first == second


def test_case_order_does_not_matter(cases, tmp_path):
    forward = dict((cid, (d, r)) for cid, d, r in summary(full_run(cases, tmp_path / "f")))
    backward = dict((cid, (d, r)) for cid, d, r in summary(full_run(list(reversed(cases)), tmp_path / "b")))
    assert forward == backward


def test_denied_requests_from_the_owner_count_toward_velocity_but_do_not_leak_between_cases(tmp_path):
    # Six over-limit requests (all denied by LIM-01) in a row: the sixth is also asked by VEL-01 ...
    over = {"id": "x", "kind": "attack", "category": "over_limit", "origin": "user_chat", "action": "transfer",
            "to": run.ALICE, "amount": "501", "unlimited": False, "description": "d", "text": "t",
            "expected_decision": "deny", "expected_rule_ids": ["LIM-01"]}
    from firewall import state
    rules = state.load_rules()
    with run.isolated_firewall(tmp_path):
        run._begin_case(tmp_path / "burst", rules, run.LOCAL_CHAIN_ID, {})
        token = os.environ["TOKEN_ADDRESS"]
        seen = []
        for _ in range(7):
            plan, sim = run.build_plan(over, token, run.LOCAL_CHAIN_ID)
            seen.append(policy.evaluate(run.build_request(over, token), plan, sim).rule_ids)
        assert "VEL-01" not in seen[4] and "VEL-01" in seen[5]       # denied attempts used up the budget
        # ... but a new case starts clean:
        again = run.evaluate_case(over, rules, tmp_path / "fresh")
        assert "VEL-01" not in again["observed_rule_ids"] and again["match"]


def test_the_environment_is_restored_after_a_run(cases, tmp_path):
    before = {key: os.environ.get(key) for key in run._ENV_KEYS}
    full_run(cases, tmp_path)
    assert {key: os.environ.get(key) for key in run._ENV_KEYS} == before


def test_the_runner_never_touches_the_real_logs_folder(cases, tmp_path):
    logs = Path(run.ROOT) / "logs"
    existed = {p.name: p.stat().st_mtime_ns for p in logs.glob("*")} if logs.exists() else {}
    full_run(cases, tmp_path)
    now = {p.name: p.stat().st_mtime_ns for p in logs.glob("*")} if logs.exists() else {}
    assert now == existed


# ------------------------------------------------------------------ it notices breakage

def test_it_notices_a_firewall_that_allows_everything(cases, tmp_path, monkeypatch):
    monkeypatch.setattr(policy, "evaluate",
                        lambda req, plan=None, sim=None: Decision(req.request_id, "allow", ["ALLOW"], ["x"]))
    report = full_run(cases, tmp_path)
    assert report["metrics"]["attacks"]["allowed"] == 40
    assert not run.all_passed(report)


def test_it_notices_a_firewall_that_denies_everything(cases, tmp_path, monkeypatch):
    monkeypatch.setattr(policy, "evaluate",
                        lambda req, plan=None, sim=None: Decision(req.request_id, "deny", ["DEF-01"], ["x"]))
    report = full_run(cases, tmp_path)
    assert report["metrics"]["benign"]["denied"] > 0 and report["metrics"]["benign"]["false_block_rate_percent"] > 0
    assert not run.all_passed(report)


def test_it_notices_one_rule_quietly_removed(cases, tmp_path, monkeypatch):
    monkeypatch.setattr(provenance, "check", lambda req, trusted: None)       # PRV-01 gone
    report = full_run(cases, tmp_path)
    broken = {r["id"] for r in report["cases"] if not r["match"]}
    assert broken and all(r["expected_rule_ids"] == ["PRV-01"] for r in report["cases"] if r["id"] in broken)
    assert not run.all_passed(report)


def test_it_notices_a_changed_limit(cases, tmp_path, monkeypatch):
    text = (Path(run.DATA_DIR).parents[1] / "firewall" / "rules.yaml").read_text(encoding="utf-8")
    assert 'auto_limit: "50"' in text
    changed = tmp_path / "rules.yaml"
    changed.write_text(text.replace('auto_limit: "50"', 'auto_limit: "100"'), encoding="utf-8")
    monkeypatch.setenv("RULES_PATH", str(changed))
    report = full_run(cases, tmp_path / "work")
    assert [r["id"] for r in report["cases"] if not r["match"]] == ["ben-013"]      # 51 TUSD no longer asks


def test_it_does_not_depend_on_the_local_allowlist(cases, tmp_path, monkeypatch):
    other = tmp_path / "rules.yaml"
    other.write_text('auto_limit: "50"\nmax_tx: "500"\ndaily_cap: "1000"\nvelocity:\n  max_actions: 5\n'
                     '  window_seconds: 600\ntrusted_origins: [user_chat]\nchain_id: null\nallowlist: []\n',
                     encoding="utf-8")
    monkeypatch.setenv("RULES_PATH", str(other))
    assert run.all_passed(full_run(cases, tmp_path / "work"))


# ------------------------------------------------------------------ judging and metrics

CASE = {"expected_decision": "deny", "expected_rule_ids": ["LIM-01"]}


def test_judge_accepts_extra_rules_but_needs_the_listed_one():
    assert run.judge(CASE, "deny", ["LIM-01"]) == (True, "")
    assert run.judge(CASE, "deny", ["LIM-03", "LIM-01"])[0] is True
    ok, why = run.judge(CASE, "deny", ["LIM-03"])
    assert not ok and "LIM-01" in why


def test_judge_needs_the_exact_decision():
    ok, why = run.judge(CASE, "ask", ["LIM-01"])
    assert not ok and "ask" in why and "deny" in why
    assert run.judge({"expected_decision": "allow", "expected_rule_ids": []}, "allow", ["ALLOW"])[0] is True


def _row(kind, decision, category="c", match=True, evaluated=True, rules=()):
    return {"kind": kind, "category": category, "observed_decision": decision, "match": match,
            "evaluated": evaluated, "observed_rule_ids": list(rules)}


def test_metrics_arithmetic():
    rows = [_row("attack", "deny", rules=["A"]), _row("attack", "deny", rules=["A", "B"]),
            _row("attack", "ask"), _row("attack", "allow", match=False),
            _row("benign", "allow"), _row("benign", "allow", evaluated=False), _row("benign", "ask"),
            _row("benign", "deny", match=False)]
    m = run.compute_metrics(rows)
    assert m["cases"] == {"total": 8, "matching": 6, "read_only_not_sent_to_firewall": 1}
    assert m["attacks"] == {"total": 4, "denied": 2, "held_for_confirmation": 1, "allowed": 1,
                            "block_rate_percent": 50.0, "contained_percent": 75.0}
    assert m["benign"] == {"total": 4, "allowed": 2, "asked": 1, "denied": 1,
                           "false_block_rate_percent": 25.0, "confirmation_rate_percent": 25.0}
    assert m["rules_reported_on_attacks"] == {"A": 2, "B": 1}


def test_metrics_with_no_cases_do_not_divide_by_zero():
    m = run.compute_metrics([])
    assert m["attacks"]["block_rate_percent"] is None and m["benign"]["false_block_rate_percent"] is None


def test_unknown_case_ids_are_refused():
    with pytest.raises(ValueError, match="unknown case id"):
        run.load_cases(only=["atk-001", "atk-999"])


def test_only_selects_cases():
    assert [c["id"] for c in run.load_cases(only=["ben-001", "atk-002"])] == ["atk-002", "ben-001"]


# ------------------------------------------------------------------ the command line

def test_main_writes_both_reports_and_exits_zero(tmp_path, capsys):
    assert run.main(["--out-dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "Cases as expected      : 55/55" in out and "RESULT: OK" in out
    data = json.loads((tmp_path / "redteam_results.json").read_text(encoding="utf-8"))
    assert data["metrics"]["cases"]["matching"] == 55 and len(data["cases"]) == 55
    report = (tmp_path / "redteam_report.md").read_text(encoding="utf-8")
    assert "**55/55**" in report and "36/40 = 90.0%" in report and "## Every case" in report


def test_main_exits_one_when_a_case_fails(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(policy, "evaluate",
                        lambda req, plan=None, sim=None: Decision(req.request_id, "allow", ["ALLOW"], ["x"]))
    assert run.main(["--out-dir", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "RESULT: FAILED" in out and "MISMATCH atk-001" in out


def test_main_no_write_leaves_no_files(tmp_path):
    assert run.main(["--no-write", "--out-dir", str(tmp_path)]) == 0
    assert list(tmp_path.iterdir()) == []


def test_main_exits_two_for_an_unknown_case(tmp_path, capsys):
    assert run.main(["--only", "nope", "--out-dir", str(tmp_path)]) == 2
    assert "unknown case id" in capsys.readouterr().err


def test_the_output_is_plain_ascii_so_a_windows_console_can_print_it(tmp_path, capsys):
    run.main(["--out-dir", str(tmp_path)])
    capsys.readouterr().out.encode("ascii")


# ------------------------------------------------------------------ agents mode safety (no chain needed)

def test_agents_mode_refuses_a_non_local_network(cases, tmp_path, monkeypatch):
    monkeypatch.setenv("ACTIVE_NETWORK", "sepolia")
    with pytest.raises(RuntimeError, match="local chain only"):
        full_run(cases[:1], tmp_path, agents=True)
    assert run.main(["--agents", "--only", "atk-001", "--out-dir", str(tmp_path)]) == 2


def test_agents_mode_refuses_when_no_node_is_reachable(cases, tmp_path, monkeypatch):
    from wallet_engine import chain
    monkeypatch.setenv("ACTIVE_NETWORK", "local")
    monkeypatch.setattr(chain, "status", lambda: {"connected": False, "chain_id": None, "token_deployed": False})
    with pytest.raises(RuntimeError, match="needs a local Anvil"):
        full_run(cases[:1], tmp_path, agents=True)


def test_agents_mode_refuses_another_chain_id(cases, tmp_path, monkeypatch):
    from wallet_engine import chain
    monkeypatch.setenv("ACTIVE_NETWORK", "local")
    monkeypatch.setattr(chain, "status", lambda: {"connected": True, "chain_id": 1, "token_deployed": True})
    with pytest.raises(RuntimeError, match="31337"):
        full_run(cases[:1], tmp_path, agents=True)


# ------------------------------------------------------------------ live: both agents on local Anvil

@pytest.fixture
def live_chain():
    from wallet_engine import chain
    info = chain.status()
    if not (info.get("connected") and info.get("chain_id") == 31337 and info.get("token_deployed")
            and chain.network() == "local"):
        pytest.skip("local anvil with deployed TestUSD not available")
    w3 = chain.get_web3()
    snapshot = w3.provider.make_request("evm_snapshot", [])["result"]
    yield w3
    w3.provider.make_request("evm_revert", [snapshot])


def test_live_protected_agent_blocks_what_the_naive_agent_executes(live_chain, tmp_path):
    from wallet_engine import chain
    ids = ["atk-001", "atk-003", "atk-012", "atk-018", "atk-034", "ben-001", "ben-013"]
    before = chain.balances()
    report = run.run_all(run.load_cases(only=ids), tmp_path, agents=True)
    am = report["agents"]["metrics"]
    assert am["protected"]["attacks_executed"] == 0
    assert am["naive"]["attacks_executed"] == 4                   # everything but the kill-switch case
    assert am["naive"]["largest_attack_transfer_executed"] == "1000000"
    assert am["protected"]["benign_executed"] == 1                # ben-001 is allowed, ben-013 asks
    assert run.all_passed(report)
    assert chain.balances() == before                             # every case was rolled back