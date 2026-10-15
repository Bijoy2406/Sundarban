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
    """Just enough rules to rehearse the script. NOT the real firewall."""

    def __init__(self):
        self.allow = {ALICE.lower(), BOB.lower()}

    def _token(self, req, plan):
        from firewall import tokens
        from wallet_engine.binding import token_binding
        b = token_binding(plan)
        return tokens.issue_token(req.request_id, b["action"], b["token"], b["to"], b["amount"])

    def evaluate(self, req, plan=None, sim=None):
        def d(kind, rules, reasons, token=None):
            return Decision(req.request_id, kind, rules, reasons, token)
        if req.origin != "user_chat":
            return d("deny", ["PRV-01"], ["untrusted source"])
        if req.unlimited:
            return d("deny", ["APR-01"], ["unlimited approvals are never allowed"])
        if req.to.lower() not in self.allow:
            return d("ask", ["ALW-01"], ["new recipient"])
        if Decimal(req.amount) > 50:
            return d("ask", ["LIM-02"], ["above the auto-approve limit"])
        return d("allow", [], [], self._token(req, plan))

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


def test_full_run_with_a_stand_in_firewall(live):
    w3, tmp = live
    from wallet_engine import chain, erc20
    token = erc20.token_contract(w3, chain.token_address())
    before = token.functions.balanceOf(ALICE).call()
    code, rows = _run(tmp, fw=StandInPolicy())

    assert code == 0
    assert len(rows) == 8
    sent = [r for r in rows if r["status"] == "sent"]
    denied = [r for r in rows if r["status"] == "denied"]
    assert len(sent) == 6 and len(denied) == 2
    for r in sent:
        assert r["tx_hash"].startswith("0x") and len(r["tx_hash"]) == 66
        assert w3.eth.get_transaction_receipt(r["tx_hash"]).status == 1
    for r in denied:
        assert r["tx_hash"] == "" and r["rule_ids"] in ("APR-01", "PRV-01")
    assert {r["rule_ids"] for r in denied} == {"APR-01", "PRV-01"}
    big = next(r for r in rows if "needs a human confirm" in r["note"])
    assert big["decision"] == "ask" and "scripted" in big["note"]
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
