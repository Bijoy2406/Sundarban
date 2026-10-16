"""firewall.preview(): the side-effect-free twin of evaluate() (used by the Preview screen).

Offline: no blockchain needed. Plans are built by hand from calldata, exactly like the engine builds them.
Also runs EVERY red-team case (firewall/redteam/*.jsonl) through the real policy engine, as a regression net.
"""
import json
from decimal import Decimal
from pathlib import Path

import pytest
from web3 import Web3

from firewall import audit, policy, state, tokens
import firewall
from shared.types import ActionRequest, SimResult, TxPlan
from wallet_engine import erc20

ROOT = Path(__file__).resolve().parents[1]
ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
BOB = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
TOKEN = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
WALLET = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
BAD = "0x0000000000000000000000000000000000000BAD"
CAFE = "0x" + "0" * 36 + "CAFE"          # a first-time recipient that is NOT on the allowlist
ENCODER = Web3().eth.contract(abi=erc20.ERC20_ABI)


@pytest.fixture(autouse=True)
def firewall_env(tmp_path, monkeypatch):
    """Alice is allowlisted, the chain is fixed (no node needed), the token is ours, tokens can be signed."""
    monkeypatch.setenv("TOKEN_ADDRESS", TOKEN)
    monkeypatch.setenv("APPROVAL_SECRET", "preview-test-secret-0123456789abcdef")
    use_rules(monkeypatch, tmp_path)


def use_rules(monkeypatch, tmp_path, chain_id=31337):
    rules = tmp_path / f"rules_{chain_id}.yaml"
    rules.write_text(f'auto_limit: "50"\nmax_tx: "500"\ndaily_cap: "1000"\n'
                     f'velocity: {{max_actions: 5, window_seconds: 600}}\ntrusted_origins: [user_chat]\n'
                     f'chain_id: {chain_id}\nallowlist: ["{ALICE}", "{BOB}"]\n')
    monkeypatch.setenv("RULES_PATH", str(rules))


def build(action="transfer", to=ALICE, amount="10", unlimited=False, origin="user_chat", chain_id=31337):
    """(request, plan, simulation) the way the agent and the engine would produce them."""
    if action == "transfer":
        fn, raw = "transfer", int(Decimal(amount).scaleb(18))
    elif action == "approve":
        fn, raw = "approve", erc20.MAX_UINT256 if unlimited else int(Decimal(amount).scaleb(18))
    else:
        fn, raw = "approve", 0
    data = ENCODER.encode_abi(fn, args=[Web3.to_checksum_address(to), raw])
    req = ActionRequest("req-" + action + to[-4:] + amount, action, TOKEN, to, amount, unlimited, origin)
    plan = TxPlan(chain_id=chain_id, from_addr=WALLET, to=TOKEN, value=0, data=data, gas=60_000,
                  function=f"{fn}(address,uint256)", args={}, summary="test")
    sim = SimResult(ok=True, revert_reason=None, outflow=amount if action == "transfer" else "0",
                    allowance_after=None)
    return req, plan, sim


def audit_entries():
    return audit.check().entries


# =============================== no side effects ===============================

def test_preview_of_an_allowed_request_changes_nothing():
    req, plan, sim = build()
    decision = firewall.preview(req, plan, sim)
    assert (decision.decision, decision.rule_ids) == ("allow", ["ALLOW"])
    assert decision.approval_token is None                    # a preview can never authorise a transaction
    assert state.actions_in_window() == 0                     # not counted toward VEL-01
    assert state.spent_last_24h() == Decimal(0)               # not counted as spending
    assert policy._PENDING == {} and tokens._USED == {}
    assert audit_entries() == 0                               # nothing written to the audit log


def test_many_previews_never_trigger_the_velocity_rule():
    for _ in range(25):                                       # the limit is 5 actions in 10 minutes
        req, plan, sim = build()
        assert firewall.preview(req, plan, sim).decision == "allow"
    assert state.actions_in_window() == 0 and state.spent_last_24h() == Decimal(0)


def test_many_previews_never_eat_the_daily_cap():
    for _ in range(30):                                       # 30 x 100 = 3000 > the 1000 daily cap
        req, plan, sim = build(amount="100")
        assert firewall.preview(req, plan, sim).decision == "ask"        # above the auto limit, never denied
    assert state.spent_last_24h() == Decimal(0)


def test_a_previewed_ask_can_not_be_confirmed():
    """Preview shows 'ask', but it opens no question: confirm() must refuse (CNF-01)."""
    req, plan, sim = build(to=CAFE)
    preview = firewall.preview(req, plan, sim)
    assert (preview.decision, preview.rule_ids) == ("ask", ["ALW-01"])
    assert policy._PENDING == {}
    confirmed = firewall.confirm(req, plan)
    assert (confirmed.decision, confirmed.rule_ids) == ("deny", ["CNF-01"])
    assert confirmed.approval_token is None


def test_evaluate_after_previews_is_counted_exactly_once():
    req, plan, sim = build()
    for _ in range(3):
        firewall.preview(req, plan, sim)
    decision = firewall.evaluate(req, plan, sim)
    assert decision.decision == "allow" and decision.approval_token
    assert state.actions_in_window() == 1
    assert state.spent_last_24h() == Decimal(10)


def test_preview_handles_bad_input_by_denying():
    assert firewall.preview("not a request").decision == "deny"
    req, plan, sim = build()
    assert firewall.preview(req, None, sim).rule_ids == ["DEF-01"]        # no plan -> deny by default


# =============================== same answer as evaluate ===============================

CASES = {
    "allowlisted transfer":         dict(),
    "new recipient":                dict(to=CAFE),
    "above auto limit":             dict(amount="200"),
    "over the maximum":             dict(amount="600"),
    "untrusted origin":             dict(origin="public_feed"),
    "unlimited approval":           dict(action="approve", amount="0", unlimited=True),
    "approve to an unknown spender": dict(action="approve", to=BAD, amount="5"),
    "look-alike address":           dict(to=ALICE[:8] + "0" * 28 + ALICE[-6:]),
    "revoke":                       dict(action="revoke", amount="0"),
}


@pytest.mark.parametrize("name", list(CASES))
def test_preview_gives_the_same_answer_as_evaluate(name):
    req, plan, sim = build(**CASES[name])
    previewed = firewall.preview(req, plan, sim)
    evaluated = firewall.evaluate(req, plan, sim)
    assert (previewed.decision, previewed.rule_ids) == (evaluated.decision, evaluated.rule_ids), name


@pytest.mark.parametrize("setup, expected", [
    ({"kill_switch": True}, ("deny", "KIL-01")),
    ({"recent_actions": 6}, ("ask", "VEL-01")),
    ({"spent_last_24h": "980"}, ("deny", "LIM-03")),
])
def test_preview_sees_the_stateful_rules_without_changing_them(setup, expected):
    if setup.get("kill_switch"):
        state.set_kill_switch(True)
    for _ in range(setup.get("recent_actions", 0)):
        state.record_action()
    if "spent_last_24h" in setup:
        state.record_spend(Decimal(setup["spent_last_24h"]))
    actions, spent = state.actions_in_window(), state.spent_last_24h()
    req, plan, sim = build(amount="50")
    decision = firewall.preview(req, plan, sim)
    assert (decision.decision, expected[1] in decision.rule_ids) == (expected[0], True)
    assert (state.actions_in_window(), state.spent_last_24h()) == (actions, spent)


# =============================== all red-team cases ===============================

def _redteam_cases():
    cases = []
    for name in ("attacks.jsonl", "benign.jsonl"):
        for line in (ROOT / "firewall" / "redteam" / name).read_text().splitlines():
            if line.strip():
                cases.append(json.loads(line))
    return [c for c in cases if c["action"] != "none"]        # "none" = a question: nothing for the firewall to decide


def _prepare(case, monkeypatch, tmp_path):
    state.reset(); tokens.reset(); policy.reset()
    setup = case.get("setup") or {}
    use_rules(monkeypatch, tmp_path, chain_id=setup.get("configured_chain_id", 31337))
    if setup.get("kill_switch"):
        state.set_kill_switch(True)
    if "spent_last_24h" in setup:
        state.record_spend(Decimal(setup["spent_last_24h"]))
    for _ in range(int(setup.get("recent_actions", 0))):
        state.record_action()
    return build(case["action"], case["to"], case["amount"], bool(case["unlimited"]), case["origin"],
                 chain_id=setup.get("plan_chain_id", setup.get("configured_chain_id", 31337)))


@pytest.mark.parametrize("case", _redteam_cases(), ids=lambda c: c["id"])
def test_red_team_case_with_preview_and_evaluate(case, monkeypatch, tmp_path):
    req, plan, sim = _prepare(case, monkeypatch, tmp_path)
    before = (state.actions_in_window(), state.spent_last_24h())
    previewed = firewall.preview(req, plan, sim)
    assert (state.actions_in_window(), state.spent_last_24h()) == before      # preview left no trace
    assert policy._PENDING == {} and audit_entries() == 0

    evaluated = firewall.evaluate(req, plan, sim)
    for answer in (previewed, evaluated):
        assert answer.decision == case["expected_decision"], (case["id"], answer.rule_ids)
        assert all(rule in answer.rule_ids for rule in case["expected_rule_ids"]), (case["id"], answer.rule_ids)
    assert (previewed.decision, previewed.rule_ids) == (evaluated.decision, evaluated.rule_ids)
