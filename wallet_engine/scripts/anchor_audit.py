"""Anchor the audit log's head hash on a public chain, and verify it later (read-only).

Why: the audit log is a hash chain. Editing or deleting a line in the middle is detected, but someone with
file access could rewrite the WHOLE chain, or cut off its last entries, and the rest would still verify.
Writing the head hash into a transaction fixes that: a block on a public chain has a timestamp nobody on this
laptop can change. After the anchor, the log can only ever be extended; any rewrite of an anchored entry shows.

What is sent: ONE transaction from the wallet to ITS OWN address, value 0, whose data is
    "sundarban-audit-v1:" + the 32-byte head hash
No token moves and no approval is made, so it does not pass through the firewall (there is nothing to decide);
the script refuses everything except this exact shape, and refuses unless the log verifies first.

    python wallet_engine/scripts/anchor_audit.py --dry-run                    # show what would be anchored
    ACTIVE_NETWORK=sepolia python wallet_engine/scripts/anchor_audit.py --yes # send the one transaction
    ACTIVE_NETWORK=sepolia python wallet_engine/scripts/anchor_audit.py --verify   # read-only check, any RPC

Defaults: the log is evidence/audit_<network>.jsonl (the one submitted as evidence) and the record is
evidence/audit_anchor_<network>.json. The anchoring does not write to the log it anchors (that would change
its head).
"""
import argparse
import importlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from firewall import audit  # noqa: E402
from wallet_engine import chain  # noqa: E402
_execute = importlib.import_module("wallet_engine.execute")   # its send lock and fee helper are reused; the package also exports a function named execute

MAGIC = b"sundarban-audit-v1:"
EXPLORERS = {"sepolia": "https://sepolia.etherscan.io/tx/"}
CHAIN_IDS = {"local": 31337, "sepolia": 11155111}
MAX_GAS = 120_000
RECEIPT_TIMEOUT = 180


class AnchorRefused(RuntimeError):
    """Nothing was sent (or the check failed). The message is safe to show."""


# ------------------------------------------------------------------ the payload

def build_data(head: str) -> str:
    """The transaction data for a head hash (64 hex characters)."""
    if not (isinstance(head, str) and len(head) == 64 and all(c in "0123456789abcdef" for c in head)):
        raise AnchorRefused("The head hash must be 64 lower-case hex characters.")
    return "0x" + (MAGIC + bytes.fromhex(head)).hex()


def parse_data(data: str):
    """The head hash inside anchor data, or None if the data is not an anchor."""
    try:
        raw = bytes.fromhex(data[2:] if data.startswith("0x") else data)
    except ValueError:
        return None
    if len(raw) != len(MAGIC) + 32 or not raw.startswith(MAGIC):
        return None
    return raw[len(MAGIC):].hex()


def default_log(network: str) -> Path:
    return ROOT / "evidence" / f"audit_{network}.jsonl"


def default_record(network: str) -> Path:
    return ROOT / "evidence" / f"audit_anchor_{network}.json"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_records(path: Path) -> list:
    if not path.exists():
        return []
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        raise AnchorRefused(f"{path.name} is not valid JSON; fix or move it first.") from None
    if not isinstance(records, list):
        raise AnchorRefused(f"{path.name} must contain a list of anchors.")
    return records


# ------------------------------------------------------------------ anchoring

def prepare(log: Path, network: str) -> dict:
    """Check the log and return what would be anchored: {'head', 'entries', 'seq', 'data'}."""
    result = audit.check(log)
    if not result.ok:
        raise AnchorRefused(f"The audit log does not verify ({result.reason}); it will not be anchored.")
    if not result.entries:
        raise AnchorRefused("The audit log is empty: nothing to anchor.")
    expected = log.with_name(f"audit_head_{network}.json")
    if expected.exists():
        try:
            recorded = json.loads(expected.read_text(encoding="utf-8"))["hash"]
        except (ValueError, KeyError, TypeError):
            raise AnchorRefused(f"{expected.name} is unreadable.") from None
        if recorded != result.head:
            raise AnchorRefused(f"The log's head differs from the one recorded in {expected.name}: "
                                "the evidence log changed after the evidence run.")
    return {"head": result.head, "entries": result.entries, "seq": result.entries - 1, "data": build_data(result.head)}


def anchor(log: Path, record: Path, network: str, yes: bool = False, dry_run: bool = False) -> dict:
    """Send the one anchoring transaction (or only describe it with dry_run). Returns the record written."""
    if network not in CHAIN_IDS:
        raise AnchorRefused(f"Unknown network {network!r}.")
    if chain.network() != network:
        raise AnchorRefused(f"ACTIVE_NETWORK is {chain.network()!r}, not {network!r}.")
    plan = prepare(log, network)
    if any(r.get("head") == plan["head"] and r.get("status") in ("confirmed", "pending") for r in _load_records(record)):
        raise AnchorRefused("This head hash is already anchored (see the record file).")
    if dry_run:
        return {"network": network, "head": plan["head"], "entries": plan["entries"], "data": plan["data"], "sent": False}
    if network != "local" and not yes:
        raise AnchorRefused(f"This sends one real {network} transaction (testnet gas). Re-run with --yes.")

    key = os.getenv(chain.key_var())
    if not key:
        raise AnchorRefused(f"{chain.key_var()} is not set in .env.")
    w3 = chain.get_web3()
    if not w3.is_connected():
        raise AnchorRefused("Cannot reach the blockchain node.")
    if w3.eth.chain_id != CHAIN_IDS[network]:
        raise AnchorRefused(f"The node is on chain {w3.eth.chain_id}, expected {CHAIN_IDS[network]}.")
    account = w3.eth.account.from_key(key)
    tx = {"from": account.address, "to": account.address, "value": 0, "data": plan["data"]}
    try:
        gas = min(int(w3.eth.estimate_gas(tx) * 1.2), MAX_GAS)
    except Exception as exc:
        raise AnchorRefused(f"The anchor transaction cannot be estimated: {type(exc).__name__}.") from None
    with _execute._SEND_LOCK:
        tx.update(gas=gas, nonce=w3.eth.get_transaction_count(account.address, "pending"),
                  chainId=w3.eth.chain_id, **_execute._fee_fields(w3))
        signed = account.sign_transaction(tx)
        tx_hash = _execute._hex(w3.eth.send_raw_transaction(signed.raw_transaction))

    entry = {"network": network, "chain_id": CHAIN_IDS[network], "wallet": account.address, "head": plan["head"],
             "seq": plan["seq"], "entries": plan["entries"], "log": log.name, "tx_hash": tx_hash,
             "explorer_url": EXPLORERS.get(network, "") + tx_hash if network in EXPLORERS else "",
             "anchored_at": _now(), "status": "pending", "block": None}
    try:
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=RECEIPT_TIMEOUT)
        entry["status"] = "confirmed" if receipt.status == 1 else "failed"
        entry["block"] = int(receipt.blockNumber)
    except Exception:
        pass                                    # broadcast, not yet mined: recorded as pending; --verify finishes the story
    records = _load_records(record)
    records.append(entry)
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    return entry


# ------------------------------------------------------------------ verifying (read-only)

def verify(record: Path, log: Path) -> list:
    """Check every recorded anchor against the chain AND the log. Returns one dict per anchor with 'ok' and 'problems'."""
    records = _load_records(record)
    if not records:
        raise AnchorRefused(f"{record.name} has no anchors to verify.")
    chain_state = audit.check(log)
    entries = {e["seq"]: e for e in audit.tail(10 ** 9, log)} if chain_state.ok else {}
    w3 = chain.get_web3()
    results = []
    for rec in records:
        problems = []
        try:
            tx = w3.eth.get_transaction(rec["tx_hash"])
            receipt = w3.eth.get_transaction_receipt(rec["tx_hash"])
            if receipt.status != 1:
                problems.append("the transaction failed on-chain")
            if w3.eth.chain_id != rec["chain_id"]:
                problems.append(f"the node is on chain {w3.eth.chain_id}, the anchor is on {rec['chain_id']}")
            if parse_data(tx["input"].hex() if hasattr(tx["input"], "hex") else str(tx["input"])) != rec["head"]:
                problems.append("the transaction data is not this anchor's head hash")
            if str(tx["from"]).lower() != str(rec["wallet"]).lower() or str(tx["to"]).lower() != str(rec["wallet"]).lower():
                problems.append("the transaction is not a self-transaction of the recorded wallet")
            if int(tx["value"]) != 0:
                problems.append("the transaction carries value")
        except Exception as exc:
            problems.append(f"the transaction could not be read from the chain ({type(exc).__name__})")
        if not chain_state.ok:
            problems.append(f"the audit log does not verify now ({chain_state.reason})")
        elif entries.get(rec["seq"], {}).get("hash") != rec["head"]:
            problems.append("the log no longer contains the anchored entry (rewritten or cut short since the anchor)")
        results.append({"tx_hash": rec["tx_hash"], "head": rec["head"], "seq": rec["seq"], "ok": not problems,
                        "problems": problems, "log_grown_since": bool(chain_state.ok and chain_state.entries > rec["seq"] + 1)})
    return results


# ------------------------------------------------------------------ command line

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--log", help="audit log to anchor (default: evidence/audit_<network>.jsonl)")
    parser.add_argument("--record", help="anchor record file (default: evidence/audit_anchor_<network>.json)")
    parser.add_argument("--yes", action="store_true", help="really send the transaction (required off the local chain)")
    parser.add_argument("--dry-run", action="store_true", help="show what would be anchored; send nothing")
    parser.add_argument("--verify", action="store_true", help="check recorded anchors against the chain and the log")
    args = parser.parse_args(argv)
    network = chain.network()
    log = Path(args.log) if args.log else default_log(network)
    record = Path(args.record) if args.record else default_record(network)
    try:
        if args.verify:
            results = verify(record, log)
            for r in results:
                print(f"{'OK     ' if r['ok'] else 'FAILED '} entry #{r['seq']} head {r['head'][:16]}... tx {r['tx_hash']}")
                for problem in r["problems"]:
                    print("        -", problem)
                if r["ok"] and r["log_grown_since"]:
                    print("        (the log has grown since; everything up to the anchor is intact)")
            ok = all(r["ok"] for r in results)
            print("RESULT: OK" if ok else "RESULT: FAILED")
            return 0 if ok else 1
        entry = anchor(log, record, network, yes=args.yes, dry_run=args.dry_run)
    except AnchorRefused as exc:
        print(f"Not done: {exc}", file=sys.stderr)
        return 2
    if args.dry_run:
        print(f"Would anchor head {entry['head']} ({entry['entries']} entries) on {network}.\n  data: {entry['data']}")
        return 0
    print(f"Anchored head {entry['head']} ({entry['entries']} entries) on {network}: {entry['status']}")
    print(f"  tx {entry['tx_hash']}" + (f"\n  {entry['explorer_url']}" if entry["explorer_url"] else ""))
    return 0 if entry["status"] in ("confirmed", "pending") else 1


if __name__ == "__main__":
    sys.exit(main())
