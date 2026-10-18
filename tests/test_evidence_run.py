"""wallet_engine/scripts/evidence_run.py (issue #11). Offline checks always run; the live ones need a
local Anvil with TestUSD deployed and use a stand-in firewall, because the real policy engine (#15)
is not written yet. Every live test is rolled back with evm_snapshot / evm_revert."""
import csv
import importlib.util
import json
import os
from decimal import Decimal
from pathlib import Path

import pytest

from shared.types import Decision

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("evidence_run", ROOT / "wallet_engine" / "scripts" / "evidence_run.py")
evidence_run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence_run)

ALICE, BOB = evidence_run.ALICE, evidence_run.BOB


class StandInPolicy:
    """Just enough rules to rehearse the script. NOT the real firewall. Unlike the real firewall (only trusted
    origins count), this stand-in counts every request toward velocity (VEL-01 asks from the 6th action) and every fired rule is reported."""

    def __init__(self):
        self.allow = {ALICE.lower(), BOB.lower()}
        self.actions = 0

    def _token(self, req, plan):
        from firewall import tokens
        from wallet_engine.binding import token_binding
        b = token_binding(plan)
        return tokens.issue_token(req.request_id, b["action"], b["token"], b["to"], b["amount"])

    def evaluate(self, req, plan=None, sim=None):
        self.actions += 1
        deny, ask = [], []
        if req.origin != "user_chat":
            deny.append(("PRV-01", "untrusted source"))
        if req.unlimited:
            deny.append(("APR-01", "unlimited approvals are never allowed"))
        if req.to.lower() not in self.allow:
            ask.append(("ALW-01", "new recipient"))
        if Decimal(req.amount) > 50:
            ask.append(("LIM-02", "above the auto-approve limit"))
        if self.actions > 5:
            ask.append(("VEL-01", "more than 5 actions in 10 minutes"))
        fired = deny + ask
        kind = "deny" if deny else "ask" if ask else "allow"
        return Decision(req.request_id, kind, [r for r, _ in fired], [w for _, w in fired],
                        self._token(req, plan) if kind == "allow" else None)

    def confirm(self, req, plan=None):
        return Decision(req.request_id, "allow", [], ["confirmed"], self._token(req, plan))


# ============================ offline ============================

def test_sepolia_needs_an_explicit_yes(monkeypatch, capsys):
    monkeypatch.setenv("ACTIVE_NETWORK", "sepolia")
    assert evidence_run.main([]) == 2
    out = capsys.readouterr().out
    assert "--yes" in out and "transfer 10 to A" in out and "DENIED" in out


def test_unknown_networks_are_refused(monkeypatch, capsys):
    monkeypatch.setenv("ACTIVE_NETWORK", "mainnet")
    assert evidence_run.main(["--yes"]) == 2
    assert "REFUSED" in capsys.readouterr().out


def test_the_scenarios_cover_what_the_issue_asks_for():
    legit = [s for s in evidence_run.SCENARIOS if "deny" not in s.expect]
    denied = [s for s in evidence_run.SCENARIOS if s.expect == {"deny"}]
    assert len(legit) >= 5 and len(denied) >= 1
    assert {s.action for s in legit} == {"transfer", "approve", "revoke"}
    assert any(s.unlimited for s in denied) and any(s.origin != "user_chat" for s in denied)
    assert not any(s.unlimited for s in legit)


def test_summary_logic():
    sent = [{"status": "sent"}] * 5
    assert evidence_run.summarize(sent + [{"status": "denied"}], 5)[0] is True
    ok, why = evidence_run.summarize(sent, 5)
    assert not ok and "denied" in why
    ok, why = evidence_run.summarize([{"status": "sent"}] * 4 + [{"status": "denied"}], 5)
    assert not ok and "only 4" in why
    ok, why = evidence_run.summarize(sent + [{"status": "denied"}, {"status": "refused"}], 5)
    assert not ok and "refused" in why
    ok, why = evidence_run.summarize(sent + [{"status": "denied", "unexpected": True}], 5)
    assert not ok and "unexpected" in why


def test_csv_header_is_written_once(tmp_path):
    p = tmp_path / "out.csv"
    evidence_run._append(p, {"action": "transfer", "status": "sent", "extra_key_is_ignored": 1})
    evidence_run._append(p, {"action": "revoke", "status": "sent"})
    rows = list(csv.DictReader(p.open()))
    assert [r["action"] for r in rows] == ["transfer", "revoke"]
    assert list(rows[0]) == evidence_run.CSV_FIELDS
    assert p.read_text().count("time,network") == 1


def test_the_sixth_action_is_expected_to_trip_velocity():
    sixth = evidence_run.SCENARIOS[5]
    assert sixth.expect == {"ask"}
    assert sixth.expected == "ask (VEL-01: sixth action within 10 minutes)"
    assert evidence_run.SCENARIOS[0].expected == "allow"          # default label is the expect set
    assert all(s.expect != {"allow"} for s in evidence_run.SCENARIOS[5:])


def test_the_preview_lists_the_expected_decisions(monkeypatch, capsys):
    monkeypatch.setenv("ACTIVE_NETWORK", "sepolia")
    evidence_run.main([])
    assert "expected: ask (VEL-01: sixth action within 10 minutes)" in capsys.readouterr().out


def test_denied_rows_explain_why_velocity_is_listed(tmp_path, monkeypatch):
    """Offline: a fake engine and the stand-in firewall; checks the CSV note only."""
    import wallet_engine
    from shared.types import SimResult, TxPlan
    fake_plan = TxPlan(31337, "0x" + "1" * 40, "0x" + "2" * 40, 0, "0x", 60000, "approve(address,uint256)", {}, "x")
    monkeypatch.setattr(wallet_engine, "plan", lambda req: fake_plan)
    monkeypatch.setattr(wallet_engine, "simulate", lambda plan: SimResult(True, None, "0", None))
    fw = StandInPolicy()
    fw.actions = 10                                                  # already past the velocity limit
    out = tmp_path / "tx.csv"
    rows = evidence_run.run([evidence_run.SCENARIOS[6]], {"A": ALICE, "B": BOB}, fw,
                            "0x" + "3" * 40, "local", out, confirm=lambda *a: False)
    assert rows[0]["status"] == "denied" and rows[0]["rule_ids"] == "APR-01 VEL-01"
    assert evidence_run.VEL_NOTE in rows[0]["note"]
    assert evidence_run.VEL_NOTE in out.read_text()


@pytest.mark.parametrize("extra", [["--yes"], []])
def test_the_rehearsal_allowlist_is_refused_off_the_local_chain(monkeypatch, capsys, tmp_path, extra):
    """--temp-allowlist swaps the allowlist for a rehearsal one: on Sepolia that would make the submitted evidence
    come from a different policy than the checked-in one."""
    monkeypatch.setenv("ACTIVE_NETWORK", "sepolia")
    from wallet_engine import chain

    def forbidden(*args, **kwargs):
        raise AssertionError("the script reached for the network: the flag was not refused first")
    monkeypatch.setattr(chain, "get_web3", forbidden)      # second safety net (conftest already blanks the Sepolia RPC and key)
    assert evidence_run.main(["--temp-allowlist", *extra, "--csv", str(tmp_path / "never_written.csv")]) == 2
    out = capsys.readouterr().out
    assert "REFUSED" in out and "--temp-allowlist" in out
    assert "PREFLIGHT" not in out                      # refused before anything touched the network
    assert not (tmp_path / "never_written.csv").exists()


class _AskThenAnswer:
    """A firewall that asks, and then answers the confirmation with a fixed decision."""

    def __init__(self, confirmed):
        self.confirmed = confirmed

    def evaluate(self, req, plan=None, sim=None):
        return Decision(req.request_id, "ask", ["LIM-02"], ["above the auto limit"], None)

    def confirm(self, req, plan=None):
        return Decision(req.request_id, self.confirmed, ["CNF-01"] if self.confirmed == "deny" else ["ALLOW"],
                        ["question expired"] if self.confirmed == "deny" else ["ok"], "tok" if self.confirmed == "allow" else None)


def _ask_row(monkeypatch, tmp_path, confirmed, scripted=False):
    import wallet_engine
    from shared.types import SimResult, TxPlan
    monkeypatch.setattr(wallet_engine, "plan", lambda req: TxPlan(
        31337, "0x" + "1" * 40, "0x" + "2" * 40, 0, "0x", 60000, "transfer(address,uint256)", {}, "x"))
    monkeypatch.setattr(wallet_engine, "simulate", lambda plan: SimResult(True, None, "1", None))
    monkeypatch.setattr(wallet_engine, "execute", lambda plan, decision: "0x" + "ab" * 32)
    confirm = evidence_run.make_confirm(auto=scripted) if scripted else (lambda *a: True)
    ask = evidence_run.SCENARIOS[4]                      # "transfer 200 to B (needs a human confirm)"
    return evidence_run.run([ask], {"A": ALICE, "B": BOB}, _AskThenAnswer(confirmed), "0x" + "3" * 40, "local",
                            tmp_path / "tx.csv", confirm=confirm)[0]


def test_no_human_confirmation_is_recorded_when_the_firewall_refused_it(monkeypatch, tmp_path):
    row = _ask_row(monkeypatch, tmp_path, "deny")
    assert row["status"] == "denied"
    assert "human confirmation" not in row["note"]
    assert "question expired" in row["note"]               # the refusal itself is still on record


def test_a_confirmed_and_allowed_ask_still_records_who_confirmed(monkeypatch, tmp_path):
    row = _ask_row(monkeypatch, tmp_path, "allow")
    assert row["status"] == "sent" and "human confirmation: typed at the prompt" in row["note"]
    scripted = _ask_row(monkeypatch, tmp_path, "allow", scripted=True)
    assert "human confirmation: scripted (--auto-confirm)" in scripted["note"]


# ============================ live (local anvil) ============================

@pytest.fixture
def live(monkeypatch, tmp_path):
    from wallet_engine import chain
    try:
        st = chain.status()
    except Exception:
        pytest.skip("chain not configured")
    if not st.get("connected") or st.get("chain_id") != 31337 or not st.get("token_deployed"):
        pytest.skip("local anvil with deployed TestUSD not available")
    recorded = json.loads((ROOT / "evidence" / "deployments.json").read_text()).get("local", {}).get("token", "")
    if recorded.lower() != os.environ["TOKEN_ADDRESS"].lower():
        pytest.skip("evidence/deployments.json (local) does not match TOKEN_ADDRESS on this chain")
    monkeypatch.setenv("ACTIVE_NETWORK", "local")
    monkeypatch.setenv("APPROVAL_SECRET", "evidence-test-secret-0123456789abcdef")
    monkeypatch.delenv("RULES_PATH", raising=False)
    w3 = chain.get_web3()
    snap = w3.provider.make_request("evm_snapshot", [])["result"]
    yield w3, tmp_path
    w3.provider.make_request("evm_revert", [snap])


def _run(tmp_path, *extra, fw=None):
    out = tmp_path / "tx.csv"
    code = evidence_run.main(["--temp-allowlist", "--auto-confirm", "--csv", str(out), *extra], fw=fw)
    return code, (list(csv.DictReader(out.open())) if out.exists() else [])


def test_full_run_with_a_stand_in_firewall(live, capsys):
    w3, tmp = live
    from wallet_engine import chain, erc20
    token = erc20.token_contract(w3, chain.token_address())
    before = token.functions.balanceOf(ALICE).call()
    code, rows = _run(tmp, fw=StandInPolicy())
    printed = capsys.readouterr().out

    assert code == 0
    assert len(rows) == 8
    sent = [r for r in rows if r["status"] == "sent"]
    denied = [r for r in rows if r["status"] == "denied"]
    assert len(sent) == 6 and len(denied) == 2
    for r in sent:
        assert r["tx_hash"].startswith("0x") and len(r["tx_hash"]) == 66
        assert w3.eth.get_transaction_receipt(r["tx_hash"]).status == 1
    for r in denied:
        assert r["tx_hash"] == "" and r["rule_ids"].split()[-1] == "VEL-01"
        assert evidence_run.VEL_NOTE in r["note"]
    assert {r["rule_ids"].split()[0] for r in denied} == {"APR-01", "PRV-01"}
    big = next(r for r in rows if "needs a human confirm" in r["note"])
    assert big["decision"] == "ask" and "scripted" in big["note"]
    sixth = rows[5]
    assert sixth["decision"] == "ask" and sixth["rule_ids"] == "VEL-01" and sixth["status"] == "sent"
    assert "UNEXPECTED" not in sixth["note"]
    assert f"note: {evidence_run.VEL_NOTE}" in printed
    # the money really moved: 10 + (approve/revoke move none) + 1 to Alice
    assert token.functions.balanceOf(ALICE).call() == before + 11 * 10**18
    # the attacker address never received anything
    from web3 import Web3
    assert token.functions.balanceOf(Web3.to_checksum_address(evidence_run.EVIL)).call() == 0
    assert token.functions.allowance(chain.wallet_address(), ALICE).call() == 0       # revoked again


def test_the_audit_trail_of_the_run_verifies(live):
    from firewall import audit
    w3, tmp = live
    code, _ = _run(tmp, fw=StandInPolicy())
    assert code == 0
    events = [e["event"]["event"] for e in audit.tail(100)]
    assert events.count("TX_SENT") == 6
    assert audit.verify() is True


def test_the_stub_firewall_is_reported_honestly_not_as_success(live):
    """Today's facade returns a token that verify_token rejects: every row must say so, exit code 1."""
    import firewall
    from shared.types import ActionRequest
    probe = firewall.evaluate(ActionRequest("probe", "transfer", "0x" + "0" * 40, "0x" + "0" * 40, "1", False, "user_chat"))
    if "STUB" not in probe.rule_ids:
        pytest.skip("the real policy engine is wired up: this honesty check no longer applies")
    w3, tmp = live
    code, rows = _run(tmp)                      # the real facade, which is still the stub on this checkout
    assert code == 1
    assert not any(r["status"] == "sent" for r in rows), "a stub decision must never end as 'sent'"
    assert all(r["status"] in ("refused", "denied", "declined", "error") for r in rows)
    assert not any(r["tx_hash"] for r in rows)


def test_a_wrong_decision_fails_the_run(live):
    """If the firewall lets the injected instruction through, the script must say NOT COMPLETE."""
    w3, tmp = live

    class TooPermissive(StandInPolicy):
        def evaluate(self, req, plan=None, sim=None):
            from shared.types import Decision
            return Decision(req.request_id, "allow", [], [], self._token(req, plan))

    code, rows = _run(tmp, fw=TooPermissive())
    assert code == 1
    assert any("UNEXPECTED" in r["note"] for r in rows)
