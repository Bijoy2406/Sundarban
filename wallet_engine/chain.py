"""Chain connection and read-only helpers (Person 1).

Everything here only READS the chain. Nothing is signed or sent.
Configuration comes from .env (ACTIVE_NETWORK, RPC_URL_LOCAL / RPC_URL_SEPOLIA,
WALLET_PRIVATE_KEY, TOKEN_ADDRESS). The private key is only used to derive the address.
"""
import json
import os
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3

from .erc20 import from_base_units, token_contract

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")


def network() -> str:
    return os.getenv("ACTIVE_NETWORK", "local")


def get_web3() -> Web3:
    var = "RPC_URL_LOCAL" if network() == "local" else "RPC_URL_SEPOLIA"
    rpc = os.getenv(var)
    if not rpc:
        raise RuntimeError(f"{var} is not set in .env")
    return Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 10}))


def key_var() -> str:
    """Which .env variable holds the signing key for the active network."""
    return "WALLET_PRIVATE_KEY" if network() == "local" else "SEPOLIA_PRIVATE_KEY"


def wallet_address() -> str:
    key = os.getenv(key_var())
    if not key:
        raise RuntimeError(f"{key_var()} is not set in .env")
    return Web3().eth.account.from_key(key).address


def token_address() -> str:
    addr = os.getenv("TOKEN_ADDRESS")
    if not addr:
        raise RuntimeError("TOKEN_ADDRESS is not set in .env (deploy TestUSD first)")
    return Web3.to_checksum_address(addr)


def status() -> dict:
    """Is the node reachable, which chain, is the token deployed there?"""
    info = {"network": network(), "connected": False, "chain_id": None, "token_deployed": False}
    try:
        w3 = get_web3()
        info["connected"] = w3.is_connected()
        if info["connected"]:
            info["chain_id"] = w3.eth.chain_id
            info["token_deployed"] = bool(w3.eth.get_code(token_address()))
    except Exception as exc:   # report, don't crash the UI
        info["error"] = str(exc)
    return info


def balances(w3: Web3 | None = None) -> dict:
    """{'ETH': '9999.99', 'TUSD': '1000000'} for the wallet address."""
    w3 = w3 or get_web3()
    owner = wallet_address()
    token = token_contract(w3, token_address())
    symbol = token.functions.symbol().call()
    decimals = token.functions.decimals().call()
    return {
        "ETH": from_base_units(w3.eth.get_balance(owner), 18),
        symbol: from_base_units(token.functions.balanceOf(owner).call(), decimals),
    }


def _deploy_block() -> int:
    """Start scanning logs at the token's deployment block (from evidence/deployments.json)."""
    path = ROOT / "evidence" / "deployments.json"
    if path.exists():
        rec = json.loads(path.read_text()).get(network(), {})
        if rec.get("token", "").lower() == token_address().lower():
            return int(rec.get("block", 0))
    return 0


def _candidate_spenders() -> list:
    """Addresses worth checking when the event scan is not possible: the allowlist and the local attacker.

    These are the only spenders our own system ever talks to, so an approval made through it is found.
    """
    found = []
    try:
        import yaml
        rules = Path(os.getenv("RULES_PATH") or ROOT / "firewall" / "rules.yaml")
        found += [str(a) for a in (yaml.safe_load(rules.read_text(encoding="utf-8")) or {}).get("allowlist") or []]
    except Exception:
        pass                                   # no rules file: fewer candidates, never a crash
    key = os.getenv("ATTACKER_PRIVATE_KEY")
    if key:
        try:
            found.append(Web3().eth.account.from_key(key).address)
        except Exception:
            pass
    unique = {}
    for address in found:
        if Web3.is_address(address):
            unique[Web3.to_checksum_address(address)] = None
    return sorted(unique)


def approvals(w3: Web3 | None = None) -> list:
    """Every spender this wallet has approved that still has a non-zero allowance.

    Found by scanning the token's Approval events for this owner, then reading the
    current allowance (events alone can be stale).

    Free public RPC plans (for example Alchemy's free tier on Sepolia) refuse a log search over more than
    a few blocks. On a public network, when the scan is refused, the allowance is read for the known
    spenders instead (see _candidate_spenders). On the local chain the scan never fails, and an error is raised.
    """
    w3 = w3 or get_web3()
    owner = wallet_address()
    token = token_contract(w3, token_address())
    decimals = token.functions.decimals().call()
    try:
        events = token.events.Approval().get_logs(from_block=_deploy_block(), argument_filters={"owner": owner})
        spenders = sorted({e["args"]["spender"] for e in events})
    except Exception:
        if network() == "local":
            raise
        spenders = _candidate_spenders()
    result = []
    for spender in spenders:
        raw = token.functions.allowance(owner, spender).call()
        if raw > 0:
            result.append({"token": token.address, "spender": spender, "allowance": from_base_units(raw, decimals)})
    return result
