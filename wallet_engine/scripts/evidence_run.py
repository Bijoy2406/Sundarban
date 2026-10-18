"""Evidence run (issue #11): push real actions through the FULL pipeline and record them.

    plan -> simulate -> firewall.evaluate -> (human confirm if 'ask') -> execute -> tx hash

Output: one CSV row per scenario in evidence/tx_hashes.csv, plus a verified copy of the audit log in
evidence/audit_<network>.jsonl and its head hash in evidence/audit_head_<network>.json.

Scenarios: 6 legitimate actions (transfers, a limited approval, a revoke, and two that need a human
confirm: one over the auto limit, and the 6th action, which trips the velocity limit) and 2 that MUST
be denied (an unlimited approval, and an instruction that arrived from a public post). Denied rows are recorded with no transaction hash.

Velocity (rule VEL-01, more than 5 actions in 10 minutes: ask) is part of the evidence on purpose:
requests from a trusted origin count toward it, so the 6th scenario is expected to be ASKED with VEL-01, and a denied
row from the owner's chat also lists VEL-01 next to the rule that denied it (requests from untrusted origins no
longer count; the submitted 16 Oct run predates that, so its public-post row lists VEL-01 too). With a long --pause the actions may
fall outside the 10-minute window and the 6th scenario is then reported as UNEXPECTED.

    # rehearsal on the local chain (anvil running, token deployed)
    python wallet_engine/scripts/evidence_run.py --temp-allowlist --auto-confirm

    # the real run on Sepolia (spends testnet gas; needs --yes)
    ACTIVE_NETWORK=sepolia python wallet_engine/scripts/evidence_run.py --yes

Honesty notes
  * 'ask' decisions are confirmed by a human at the prompt, or by --auto-confirm (the CSV note says
    "scripted" when that flag was used). Do not present scripted confirmations as human ones.
  * The firewall is whatever `firewall.evaluate` / `firewall.confirm` are on this checkout.
    Real evidence needs the real policy engine (issue #15); with the stub every row ends "refused".
"""
import argparse
import csv
import json
import os
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

from shared.redact import redact  # noqa: E402

load_dotenv(ROOT / ".env")

ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"   # Anvil public test account #1
BOB = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"     # Anvil public test account #2
EVIL = "0x" + "0" * 36 + "0BAD"                          # an obviously fake, non-allowlisted address

CHAIN_IDS = {"local": 31337, "sepolia": 11155111}
EXPLORERS = {"sepolia": "https://sepolia.etherscan.io/tx/"}
CSV_FIELDS = ["time", "network", "action", "token", "to", "amount", "decision_id", "tx_hash",
              "explorer_url", "status", "decision", "rule_ids", "note"]


@dataclass
class Scenario:
    name: str
    action: str
    to: str                      # "A", "B" (recipients) or a literal address
    amount: str = "0"
    unlimited: bool = False
    origin: str = "user_chat"
    expect: set = field(default_factory=lambda: {"allow"})   # acceptable FIRST decisions
    expect_label: str = ""       # human-readable expected decision; defaults to the sorted `expect` set

    @property
    def expected(self) -> str:
        return self.expect_label or "/".join(sorted(self.expect))


VEL_RULE = "VEL-01"
VEL_NOTE = ("requests from a trusted origin count toward the velocity limit (VEL-01: more than 5 actions in 10 minutes), "
            "so a denied row from the owner's chat can also list VEL-01 next to the rule that denied it")


SCENARIOS = [
    Scenario("transfer 10 to A", "transfer", "A", "10"),
    Scenario("transfer 30 to B", "transfer", "B", "30"),
    Scenario("limited approval of 20 for A", "approve", "A", "20"),
    Scenario("revoke A", "revoke", "A", "0", expect={"allow", "ask"}),
    Scenario("transfer 200 to B (needs a human confirm)", "transfer", "B", "200", expect={"ask"}),
    Scenario("transfer 1 to A", "transfer", "A", "1", expect={"ask"},
             expect_label="ask (VEL-01: sixth action within 10 minutes)"),
    Scenario("DENIED: unlimited approval for A", "approve", "A", "0", unlimited=True, expect={"deny"}),
    Scenario("DENIED: instruction from a public post", "transfer", EVIL, "25", origin="public_feed",
             expect={"deny"}),
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append(csv_path: Path, row: dict) -> None:
    new = not csv_path.exists() or csv_path.stat().st_size == 0
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        if new:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in CSV_FIELDS})


def run(scenarios, recipients, fw, token_address, network, csv_path, confirm, pause=0.0) -> list[dict]:
    """Run the scenarios in order. Returns one dict per scenario (also appended to the CSV)."""
    import wallet_engine
    from shared.types import ActionRequest
    from wallet_engine import ExecutionFailed, ExecutionPending, ExecutionRefused

    results = []
    for s in scenarios:
        to = recipients.get(s.to, s.to)
        req = ActionRequest(request_id=str(uuid.uuid4()), action=s.action, token=token_address, to=to,
                            amount=s.amount, unlimited=s.unlimited, origin=s.origin)
        row = {"time": _now(), "network": network, "action": s.action, "token": token_address, "to": to,
               "amount": "unlimited" if s.unlimited else s.amount, "decision_id": req.request_id,
               "status": "", "decision": "", "rule_ids": "", "note": s.name, "first": ""}
        try:
            plan = wallet_engine.plan(req)
            sim = wallet_engine.simulate(plan)
            decision = fw.evaluate(req, plan, sim)
            row["first"] = row["decision"] = decision.decision
            row["rule_ids"] = " ".join(decision.rule_ids)
            if decision.decision == "ask":
                if confirm(req, plan, decision):
                    decision = fw.confirm(req, plan)
                    if decision.decision == "allow":          # only an accepted confirmation counts as one
                        row["note"] += " | human confirmation: " + ("scripted (--auto-confirm)" if getattr(confirm, "scripted", False) else "typed at the prompt")
                else:
                    row["status"] = "declined"
            if row["status"] == "declined":
                pass
            elif decision.decision == "deny":
                row["status"] = "denied"
                row["note"] += " | " + "; ".join(decision.reasons)
                if VEL_RULE in decision.rule_ids:
                    row["note"] += " | " + VEL_NOTE
            elif decision.decision == "allow":
                tx_hash = wallet_engine.execute(plan, decision)
                row["status"] = "sent"
                row["tx_hash"] = tx_hash
                row["explorer_url"] = EXPLORERS.get(network, "") + tx_hash if network in EXPLORERS else ""
            else:
                row["status"] = "error"
                row["note"] += f" | unknown decision {decision.decision!r}"
        except ExecutionRefused as exc:
            row["status"] = "refused"
            row["note"] += f" | execute refused: {redact(exc)}"
        except ExecutionFailed as exc:
            row["status"] = "failed"
            row["note"] += f" | {redact(exc)}"
        except ExecutionPending as exc:                  # broadcast, outcome unknown: keep the hash, do not count it as sent
            row["status"] = "pending"
            row["tx_hash"] = exc.tx_hash
            row["note"] += " | broadcast but no receipt yet (not counted as sent)"
        except Exception as exc:                         # report and keep going; never hide it
            row["status"] = "error"
            row["note"] += f" | {type(exc).__name__}: {redact(exc)}"
        if row["first"] and row["first"] not in s.expect:
            row["note"] += f" | UNEXPECTED first decision {row['first']!r} (expected {s.expected})"
            row["unexpected"] = True
        _append(csv_path, row)
        results.append(row)
        if pause:
            time.sleep(pause)
    return results


def summarize(results: list[dict], min_sent: int) -> tuple[bool, str]:
    sent = [r for r in results if r["status"] == "sent"]
    denied = [r for r in results if r["status"] == "denied"]
    problems = []
    if len(sent) < min_sent:
        problems.append(f"only {len(sent)} transactions were sent (need at least {min_sent})")
    if not denied:
        problems.append("no action was denied (the evidence needs at least one denied action)")
    odd = [r for r in results if r.get("unexpected")]
    if odd:
        problems.append(f"{len(odd)} scenario(s) got an unexpected decision")
    bad = [r for r in results if r["status"] in ("refused", "failed", "error", "declined")]
    if bad:
        problems.append(f"{len(bad)} scenario(s) ended refused/failed/error/declined")
    return (not problems), "; ".join(problems)


def make_confirm(auto: bool):
    def confirm(req, plan, decision) -> bool:
        if auto:
            return True
        print(f"\n  The firewall asks for confirmation: {plan.summary}")
        print(f"  reasons: {'; '.join(decision.reasons) or '(none)'}")
        return input("  Send it? [y/N] ").strip().lower() in ("y", "yes")
    confirm.scripted = auto
    return confirm


def main(argv=None, fw=None) -> int:
    parser = argparse.ArgumentParser(description="Run the evidence scenarios through the full pipeline.")
    parser.add_argument("--yes", action="store_true", help="required on Sepolia: really send testnet transactions")
    parser.add_argument("--auto-confirm", action="store_true", help="confirm 'ask' decisions without prompting (recorded as scripted)")
    parser.add_argument("--temp-allowlist", action="store_true",
                        help="use a temporary rules file whose allowlist is the two recipients (rehearsal only)")
    parser.add_argument("--recipient-a", default=ALICE)
    parser.add_argument("--recipient-b", default=BOB)
    parser.add_argument("--csv", default=str(ROOT / "evidence" / "tx_hashes.csv"))
    parser.add_argument("--pause", type=float, default=0.0, help="seconds to wait between scenarios")
    parser.add_argument("--min-sent", type=int, default=5)
    args = parser.parse_args(argv)

    network = os.getenv("ACTIVE_NETWORK", "local")
    if network not in CHAIN_IDS:
        print(f"REFUSED: ACTIVE_NETWORK must be 'local' or 'sepolia' (got {network!r})")
        return 2
    if args.temp_allowlist and network != "local":
        print(f"REFUSED: --temp-allowlist is for rehearsals on the local chain only (ACTIVE_NETWORK is {network!r}). "
              "Evidence on a public network must come from the checked-in firewall/rules.yaml.")
        return 2
    if network != "local" and not args.yes:
        print(f"This will send REAL transactions on {network} (test tokens, gas paid in test ETH).")
        print("Scenarios:")
        for s in SCENARIOS:
            print(f"  - {s.name}  (expected: {s.expected})")
        print("Re-run with --yes to proceed.")
        return 2

    # one audit log per network, inside evidence/, so the copy we submit holds only this evidence
    audit_path = ROOT / "evidence" / f"audit_{network}.jsonl"
    os.environ.setdefault("AUDIT_LOG_PATH", str(audit_path))

    deployments = ROOT / "evidence" / "deployments.json"
    if deployments.exists():
        recorded = json.loads(deployments.read_text()).get(network, {}).get("token")
        if recorded:
            os.environ["TOKEN_ADDRESS"] = recorded

    import firewall as firewall_module
    from firewall import audit, state
    from wallet_engine import chain, erc20
    fw = fw or firewall_module

    # ---- preflight
    try:
        w3 = chain.get_web3()
        if not w3.is_connected():
            raise RuntimeError("cannot reach the node")
        if w3.eth.chain_id != CHAIN_IDS[network]:
            raise RuntimeError(f"node is chain {w3.eth.chain_id}, expected {CHAIN_IDS[network]} for {network}")
        token_address = chain.token_address()
        if not w3.eth.get_code(token_address):
            raise RuntimeError(f"TestUSD is not deployed at {token_address} on {network}")
        owner = chain.wallet_address()
        balances = chain.balances(w3)
        if erc20.to_base_units(balances["TUSD"]) < erc20.to_base_units("300"):
            raise RuntimeError(f"wallet holds only {balances['TUSD']} TUSD (need about 300)")
        if w3.eth.get_balance(owner) < 10**15:
            raise RuntimeError("wallet has less than 0.001 ETH for gas")
        if not os.getenv("APPROVAL_SECRET"):
            raise RuntimeError("APPROVAL_SECRET is not set in .env")
    except Exception as exc:
        print(f"PREFLIGHT FAILED: {redact(exc)}")
        return 2

    recipients = {"A": args.recipient_a, "B": args.recipient_b}
    temp_rules = None
    if args.temp_allowlist:
        import yaml
        cfg = yaml.safe_load(state.DEFAULT_RULES_PATH.read_text())
        cfg["allowlist"] = list(recipients.values())
        cfg["chain_id"] = CHAIN_IDS[network]
        handle = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        yaml.safe_dump(cfg, handle)
        handle.close()
        temp_rules = handle.name
        os.environ["RULES_PATH"] = temp_rules
        print(f"(rehearsal) using a temporary allowlist: {temp_rules}")
    else:
        allow = {a.lower() for a in state.load_rules()["allowlist"]}
        missing = [a for a in recipients.values() if a.lower() not in allow]
        if missing:
            print("PREFLIGHT FAILED: these recipients are not in firewall/rules.yaml 'allowlist':")
            for a in missing:
                print("   -", a)
            print("Add them (and set chain_id), or use --temp-allowlist for a rehearsal.")
            return 2

    print(f"network={network} token={token_address}\nwallet={owner}\ncsv={args.csv}\n")
    results = run(SCENARIOS, recipients, fw, token_address, network, Path(args.csv),
                  make_confirm(args.auto_confirm), pause=args.pause)

    width = max(len(r["note"].split(" | ")[0]) for r in results)
    for r in results:
        label = r["note"].split(" | ")[0]
        print(f"  {r['status']:9s} {label:{width}s}  {r['decision']:5s} {r['rule_ids']:12s} {r['tx_hash'] if r.get('tx_hash') else ''}")
    if any(r["status"] == "denied" and VEL_RULE in r["rule_ids"].split() for r in results):
        print(f"\n  note: {VEL_NOTE}")

    ok, why = summarize(results, args.min_sent)
    head = audit.head()
    if head:
        head_file = Path(os.environ["AUDIT_LOG_PATH"]).with_name(f"audit_head_{network}.json")   # beside the log
        head_file.write_text(json.dumps({"network": network, "time": _now(), **head}, indent=2) + "\n")
    print(f"\naudit log verified: {audit.verify(expected_head=head['hash'] if head else None)}"
          f"   head: {head['hash'][:16] + '...' if head else '(empty)'}")
    print("RESULT:", "OK, evidence is complete" if ok else f"NOT COMPLETE: {why}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
