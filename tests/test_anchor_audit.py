"""wallet_engine/scripts/anchor_audit.py: write the audit log's head hash into a transaction, verify it later.

Offline checks always run. The live ones need a local Anvil with TestUSD deployed (chain 31337) and are rolled
back with evm_snapshot / evm_revert.
"""
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from firewall import audit

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("anchor_audit", ROOT / "wallet_engine" / "scripts" / "anchor_audit.py")
anchor_audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(anchor_audit)

HEAD = "63b7de471b31b6f57f336c438e214ee526d27b4caa6f5da5f007af25b89a3f85"


def make_log(path: Path, entries: int = 4) -> Path:
    for index in range(entries):
        audit.log({"event": "DECISION", "request_id": f"r{index}", "decision": "allow"})
    return audit.default_path() if path is None else path


# ------------------------------------------------------------------ the payload

def test_the_data_is_the_label_plus_the_32_byte_head():
    data = anchor_audit.build_data(HEAD)
    assert data.startswith("0x" + b"sundarban-audit-v1:".hex()) and data.endswith(HEAD)
    assert len(bytes.fromhex(data[2:])) == len(b"sundarban-audit-v1:") + 32


def test_parse_is_the_exact_inverse_and_rejects_everything_else():
    assert anchor_audit.parse_data(anchor_audit.build_data(HEAD)) == HEAD
    assert anchor_audit.parse_data(anchor_audit.build_data(HEAD)[2:]) == HEAD          # without 0x
    for junk in ("0x", "0x1234", "zz", "0x" + b"other-label-0123456:".hex() + HEAD,
                 anchor_audit.build_data(HEAD) + "00", anchor_audit.build_data(HEAD)[:-2]):
        assert anchor_audit.parse_data(junk) is None


@pytest.mark.parametrize("bad", ["", "abc", HEAD.upper(), HEAD[:-1], HEAD + "0", "g" * 64, None, 5])
def test_a_malformed_head_is_refused(bad):
    with pytest.raises(anchor_audit.AnchorRefused):
        anchor_audit.build_data(bad)


# ------------------------------------------------------------------ a damaged record file must give a verdict, not a traceback

GOOD_LOG = ROOT / "evidence" / "audit_sepolia.jsonl"
WALLET = "0xB89C8A9826cac01E3b4A01873Bd0C27553567609"
FULL = {"tx_hash": "0x" + "ab" * 32, "head": HEAD, "wallet": WALLET, "chain_id": 11155111, "seq": 15}


@pytest.fixture
def offline_chain(monkeypatch):
    """verify() reads the chain; here the node is unreachable, so a well-shaped record fails for THAT reason."""
    from types import SimpleNamespace

    def unreachable(*args, **kwargs):
        raise ConnectionError("no node in this test")
    eth = SimpleNamespace(get_transaction=unreachable, get_transaction_receipt=unreachable, chain_id=11155111)
    monkeypatch.setattr(anchor_audit.chain, "get_web3", lambda: SimpleNamespace(eth=eth))


def _verify(tmp_path, records, capsys):
    record = tmp_path / "anchors.json"
    record.write_text(json.dumps(records), encoding="utf-8")
    code = anchor_audit.main(["--verify", "--log", str(GOOD_LOG), "--record", str(record)])
    return code, capsys.readouterr().out


@pytest.mark.parametrize("records", [
    ["just a string"],
    [42],
    [None],
    [["a", "list"]],
    [{k: v for k, v in FULL.items() if k != "seq"}],                 # no 'seq'
    [{k: v for k, v in FULL.items() if k != "head"}],                # no 'head'
    [{k: v for k, v in FULL.items() if k != "tx_hash"}],             # no 'tx_hash'
    [{**FULL, "seq": "15"}],                                          # wrong type
    [{**FULL, "chain_id": True}],                                     # a bool is not a chain id
    [{**FULL, "head": 5}],
    [{}],
])
def test_a_malformed_record_is_reported_as_failed_not_raised(tmp_path, capsys, offline_chain, records):
    code, out = _verify(tmp_path, records, capsys)
    assert code == 1
    assert "RESULT: FAILED" in out and "Traceback" not in out


def test_one_bad_record_among_good_shapes_still_fails_the_whole_check(tmp_path, capsys, offline_chain):
    code, out = _verify(tmp_path, [FULL, "oops"], capsys)
    assert code == 1 and out.count("FAILED") >= 2                     # the bad record AND the overall result
    assert "not a record" in out or "malformed" in out


def test_verify_returns_problems_for_a_bad_record_without_raising(tmp_path, offline_chain):
    record = tmp_path / "anchors.json"
    record.write_text(json.dumps(["x", {"tx_hash": "0x1"}]), encoding="utf-8")
    results = anchor_audit.verify(record, GOOD_LOG)
    assert [r["ok"] for r in results] == [False, False]
    assert all(r["problems"] for r in results)


# ------------------------------------------------------------------ what may be anchored

def test_the_shipped_sepolia_evidence_log_is_anchorable():
    plan = anchor_audit.prepare(ROOT / "evidence" / "audit_sepolia.jsonl", "sepolia")
    assert plan["head"] == HEAD and plan["entries"] == 16 and plan["seq"] == 15


def test_a_log_that_does_not_verify_is_never_anchored(tmp_path):
    log = tmp_path / "audit_sepolia.jsonl"
    shutil.copy(ROOT / "evidence" / "audit_sepolia.jsonl", log)
    data = log.read_bytes()
    assert b"DECISION" in data
    log.write_bytes(data.replace(b"DECISION", b"DECISIOX", 1))
    with pytest.raises(anchor_audit.AnchorRefused, match="does not verify"):
        anchor_audit.prepare(log, "sepolia")


def test_an_empty_or_missing_log_is_refused(tmp_path):
    for log in (tmp_path / "none.jsonl", tmp_path / "empty.jsonl"):
        if log.name == "empty.jsonl":
            log.write_bytes(b"")
        with pytest.raises(anchor_audit.AnchorRefused, match="empty"):
            anchor_audit.prepare(log, "local")


def test_the_head_must_still_match_the_one_recorded_at_the_evidence_run(tmp_path):
    log = tmp_path / "audit_sepolia.jsonl"
    shutil.copy(ROOT / "evidence" / "audit_sepolia.jsonl", log)
    (tmp_path / "audit_head_sepolia.json").write_text(json.dumps({"hash": "0" * 64}))
    with pytest.raises(anchor_audit.AnchorRefused, match="changed after the evidence run"):
        anchor_audit.prepare(log, "sepolia")


def test_a_dry_run_sends_nothing_and_needs_no_key(tmp_path, monkeypatch):
    monkeypatch.setenv("ACTIVE_NETWORK", "sepolia")
    monkeypatch.delenv("SEPOLIA_PRIVATE_KEY", raising=False)
    entry = anchor_audit.anchor(ROOT / "evidence" / "audit_sepolia.jsonl", tmp_path / "rec.json", "sepolia", dry_run=True)
    assert entry["sent"] is False and entry["head"] == HEAD and not (tmp_path / "rec.json").exists()


def test_a_public_network_needs_an_explicit_yes(tmp_path, monkeypatch):
    monkeypatch.setenv("ACTIVE_NETWORK", "sepolia")
    with pytest.raises(anchor_audit.AnchorRefused, match="--yes"):
        anchor_audit.anchor(ROOT / "evidence" / "audit_sepolia.jsonl", tmp_path / "rec.json", "sepolia", yes=False)


def test_the_network_must_match_the_active_one(tmp_path, monkeypatch):
    monkeypatch.setenv("ACTIVE_NETWORK", "local")
    with pytest.raises(anchor_audit.AnchorRefused, match="ACTIVE_NETWORK"):
        anchor_audit.anchor(ROOT / "evidence" / "audit_sepolia.jsonl", tmp_path / "rec.json", "sepolia", yes=True)


def test_an_unknown_network_is_refused(tmp_path):
    with pytest.raises(anchor_audit.AnchorRefused, match="Unknown network"):
        anchor_audit.anchor(tmp_path / "x", tmp_path / "r", "mainnet", yes=True)


def test_main_exit_codes(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ACTIVE_NETWORK", "sepolia")
    log = str(ROOT / "evidence" / "audit_sepolia.jsonl")
    assert anchor_audit.main(["--dry-run", "--log", log, "--record", str(tmp_path / "r.json")]) == 0
    assert "Would anchor head " + HEAD in capsys.readouterr().out
    assert anchor_audit.main(["--log", log, "--record", str(tmp_path / "r.json")]) == 2          # no --yes
    assert "Not done" in capsys.readouterr().err
    assert anchor_audit.main(["--verify", "--log", log, "--record", str(tmp_path / "missing.json")]) == 2


# ------------------------------------------------------------------ live: a real transaction on local Anvil

@pytest.fixture
def anvil(monkeypatch):
    from wallet_engine import chain
    try:
        info = chain.status()
    except Exception:
        pytest.skip("chain not configured")
    if not (info.get("connected") and info.get("chain_id") == 31337 and chain.network() == "local"):
        pytest.skip("local anvil not available")
    monkeypatch.setenv("ACTIVE_NETWORK", "local")
    w3 = chain.get_web3()
    snapshot = w3.provider.make_request("evm_snapshot", [])["result"]
    yield w3
    w3.provider.make_request("evm_revert", [snapshot])


def anchored(tmp_path):
    log = tmp_path / "audit_local.jsonl"
    for index in range(5):
        audit.log({"event": "DECISION", "request_id": f"r{index}", "decision": "allow"})
    return Path(audit.default_path()), tmp_path / "audit_anchor_local.json"


def test_live_anchor_then_verify(anvil, tmp_path):
    log, record = anchored(tmp_path)
    entry = anchor_audit.anchor(log, record, "local")
    assert entry["status"] == "confirmed" and entry["head"] == audit.head(log)["hash"] and entry["seq"] == 4
    tx = anvil.eth.get_transaction(entry["tx_hash"])
    assert tx["from"] == tx["to"] == entry["wallet"] and tx["value"] == 0
    assert anchor_audit.parse_data(tx["input"].hex()) == entry["head"]
    [result] = anchor_audit.verify(record, log)
    assert result["ok"] and result["problems"] == [] and result["log_grown_since"] is False


def test_live_the_log_may_grow_after_the_anchor(anvil, tmp_path):
    log, record = anchored(tmp_path)
    anchor_audit.anchor(log, record, "local")
    audit.log({"event": "DECISION", "request_id": "later", "decision": "deny"})
    [result] = anchor_audit.verify(record, log)
    assert result["ok"] and result["log_grown_since"] is True


def test_live_the_same_head_cannot_be_anchored_twice(anvil, tmp_path):
    log, record = anchored(tmp_path)
    anchor_audit.anchor(log, record, "local")
    with pytest.raises(anchor_audit.AnchorRefused, match="already anchored"):
        anchor_audit.anchor(log, record, "local")
    audit.log({"event": "DECISION", "request_id": "next", "decision": "allow"})
    assert anchor_audit.anchor(log, record, "local")["seq"] == 5                      # a new head is fine
    assert len(json.loads(record.read_text())) == 2


def test_live_cutting_off_the_last_entries_is_caught(anvil, tmp_path):
    log, record = anchored(tmp_path)
    anchor_audit.anchor(log, record, "local")
    lines = log.read_bytes().split(b"\n")[:-1]
    log.write_bytes(b"\n".join(lines[:-2]) + b"\n")                                  # a valid, shorter chain
    assert audit.check(log).ok                                                       # the chain alone cannot tell
    [result] = anchor_audit.verify(record, log)
    assert not result["ok"] and any("rewritten or cut short" in p for p in result["problems"])


def test_live_rewriting_the_whole_chain_is_caught(anvil, tmp_path, monkeypatch):
    log, record = anchored(tmp_path)
    anchor_audit.anchor(log, record, "local")
    log.unlink()
    for index in range(5):                                                           # a different, perfectly valid chain
        audit.log({"event": "DECISION", "request_id": f"forged{index}", "decision": "allow"})
    assert audit.check(log).ok
    [result] = anchor_audit.verify(record, log)
    assert not result["ok"]


def test_live_a_forged_record_is_caught(anvil, tmp_path):
    log, record = anchored(tmp_path)
    entry = anchor_audit.anchor(log, record, "local")
    forged = json.loads(record.read_text())
    forged[0]["head"] = "0" * 64
    record.write_text(json.dumps(forged))
    [result] = anchor_audit.verify(record, log)
    assert not result["ok"] and any("not this anchor's head" in p for p in result["problems"])
    assert entry["tx_hash"] == result["tx_hash"]


def test_live_a_modified_log_is_caught(anvil, tmp_path):
    log, record = anchored(tmp_path)
    anchor_audit.anchor(log, record, "local")
    log.write_bytes(log.read_bytes().replace(b"allow", b"deny!", 1))
    [result] = anchor_audit.verify(record, log)
    assert not result["ok"] and any("does not verify" in p for p in result["problems"])


# ------------------------------------------------------------------ the evidence that ships in the repository

def test_the_shipped_anchor_record_matches_the_shipped_evidence():
    records = json.loads((ROOT / "evidence" / "audit_anchor_sepolia.json").read_text())
    head_file = json.loads((ROOT / "evidence" / "audit_head_sepolia.json").read_text())
    checked = audit.check(ROOT / "evidence" / "audit_sepolia.jsonl")
    assert checked.ok and len(records) >= 1
    first = records[0]
    assert first["head"] == head_file["hash"] == checked.head and first["seq"] == head_file["seq"] == checked.entries - 1
    assert first["network"] == "sepolia" and first["chain_id"] == 11155111 and first["status"] == "confirmed"
    assert first["explorer_url"].endswith(first["tx_hash"]) and len(first["tx_hash"]) == 66
    assert (ROOT / "evidence" / "tx_hashes.csv").read_text().lower().count(first["tx_hash"].lower()) == 0   # a separate kind of transaction
