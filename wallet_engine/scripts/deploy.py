"""Deploy the TestUSD token (Person 1).

Usage (from the repo root, venv active, anvil running for ACTIVE_NETWORK=local):
    cd wallet_engine && forge build && cd ..
    python wallet_engine/scripts/deploy.py

Reads RPC and key from .env. Never prints the private key.
Writes the result to evidence/deployments.json (committed on purpose: it is evidence).
"""
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")

network = os.getenv("ACTIVE_NETWORK", "local")
rpc_var = "RPC_URL_LOCAL" if network == "local" else "RPC_URL_SEPOLIA"
key_var = "WALLET_PRIVATE_KEY" if network == "local" else "SEPOLIA_PRIVATE_KEY"
rpc = os.getenv(rpc_var)
key = os.getenv(key_var)
if not rpc or not key:
    sys.exit(f"Set {rpc_var} and {key_var} in .env first.")

w3 = Web3(Web3.HTTPProvider(rpc))
if not w3.is_connected():
    sys.exit(f"Cannot reach the node at {rpc_var}. Is anvil running?")

artifact_path = ROOT / "wallet_engine" / "out" / "TestUSD.sol" / "TestUSD.json"
if not artifact_path.exists():
    sys.exit("Build first: cd wallet_engine && forge build")
artifact = json.loads(artifact_path.read_text())

acct = w3.eth.account.from_key(key)
contract = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"]["object"])
tx = contract.constructor().build_transaction(
    {"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address), "chainId": w3.eth.chain_id}
)
signed = acct.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
if receipt.status != 1:
    sys.exit("Deployment transaction failed.")

record = {
    "network": network,
    "chain_id": w3.eth.chain_id,
    "token": receipt.contractAddress,
    "deployer": acct.address,
    "tx_hash": tx_hash.hex() if tx_hash.hex().startswith("0x") else "0x" + tx_hash.hex(),
    "block": receipt.blockNumber,
}
out = ROOT / "evidence" / "deployments.json"
data = json.loads(out.read_text()) if out.exists() else {}
data[network] = record
out.write_text(json.dumps(data, indent=2) + "\n")

print(f"TestUSD deployed on {network} (chain id {record['chain_id']})")
print(f"  token address: {record['token']}")
print(f"  tx hash:       {record['tx_hash']}")
print(f"Put this in .env:  TOKEN_ADDRESS={record['token']}")
