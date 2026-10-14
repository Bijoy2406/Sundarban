"""ERC-20 helpers (Person 1): unit conversion, building transactions, decoding calldata.

Amounts are always strings in token units (e.g. "12.5") at the edges and integers
(base units, 18 decimals) on-chain. Never use float for money.
"""
from decimal import Decimal, InvalidOperation

from web3 import Web3

from shared.types import ActionRequest, TxPlan

MAX_UINT256 = 2**256 - 1

# Minimal standard ERC-20 ABI: enough for every action this project uses.
ERC20_ABI = [
    {"type": "function", "name": "name", "stateMutability": "view", "inputs": [], "outputs": [{"name": "", "type": "string"}]},
    {"type": "function", "name": "symbol", "stateMutability": "view", "inputs": [], "outputs": [{"name": "", "type": "string"}]},
    {"type": "function", "name": "decimals", "stateMutability": "view", "inputs": [], "outputs": [{"name": "", "type": "uint8"}]},
    {"type": "function", "name": "totalSupply", "stateMutability": "view", "inputs": [], "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "balanceOf", "stateMutability": "view",
     "inputs": [{"name": "account", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "allowance", "stateMutability": "view",
     "inputs": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}],
     "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "transfer", "stateMutability": "nonpayable",
     "inputs": [{"name": "to", "type": "address"}, {"name": "value", "type": "uint256"}],
     "outputs": [{"name": "", "type": "bool"}]},
    {"type": "function", "name": "approve", "stateMutability": "nonpayable",
     "inputs": [{"name": "spender", "type": "address"}, {"name": "value", "type": "uint256"}],
     "outputs": [{"name": "", "type": "bool"}]},
    {"type": "function", "name": "transferFrom", "stateMutability": "nonpayable",
     "inputs": [{"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "value", "type": "uint256"}],
     "outputs": [{"name": "", "type": "bool"}]},
    {"type": "event", "name": "Approval", "anonymous": False,
     "inputs": [{"name": "owner", "type": "address", "indexed": True},
                {"name": "spender", "type": "address", "indexed": True},
                {"name": "value", "type": "uint256", "indexed": False}]},
    {"type": "event", "name": "Transfer", "anonymous": False,
     "inputs": [{"name": "from", "type": "address", "indexed": True},
                {"name": "to", "type": "address", "indexed": True},
                {"name": "value", "type": "uint256", "indexed": False}]},
]

SIGNATURES = {
    "transfer": "transfer(address,uint256)",
    "approve": "approve(address,uint256)",
    "transferFrom": "transferFrom(address,address,uint256)",
}

FALLBACK_GAS = 100_000   # used only when the node cannot estimate (e.g. the tx would revert)


def to_base_units(amount: str, decimals: int = 18) -> int:
    """'12.5' -> 12500000000000000000. Rejects negatives, junk and too many decimals."""
    try:
        value = Decimal(str(amount).strip())
    except InvalidOperation:
        raise ValueError(f"Not a number: {amount!r}")
    if value < 0:
        raise ValueError("Amount cannot be negative")
    raw = value * (Decimal(10) ** decimals)
    if raw != raw.to_integral_value():
        raise ValueError(f"Too many decimal places (max {decimals})")
    return int(raw)


def from_base_units(raw: int, decimals: int = 18) -> str:
    """12500000000000000000 -> '12.5'. MAX_UINT256 -> 'unlimited'."""
    if raw == MAX_UINT256:
        return "unlimited"
    text = format(Decimal(raw) / (Decimal(10) ** decimals), "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def short(addr: str) -> str:
    return f"{addr[:6]}...{addr[-4:]}"


def token_contract(w3: Web3, token_address: str):
    return w3.eth.contract(address=Web3.to_checksum_address(token_address), abi=ERC20_ABI)


def plan(w3: Web3, req: ActionRequest, from_addr: str) -> TxPlan:
    """Turn an ActionRequest into the exact transaction that would be signed. Sends nothing."""
    if req.token.upper() == "ETH":
        raise ValueError("Only ERC-20 actions are supported (no plain ETH transfers)")
    token = token_contract(w3, req.token)
    symbol = token.functions.symbol().call()
    decimals = token.functions.decimals().call()
    to = Web3.to_checksum_address(req.to)

    if req.action == "transfer":
        raw = to_base_units(req.amount, decimals)
        fn_name, args = "transfer", [to, raw]
        summary = f"Send {req.amount} {symbol} to {short(to)}"
    elif req.action == "approve":
        raw = MAX_UINT256 if req.unlimited else to_base_units(req.amount, decimals)
        fn_name, args = "approve", [to, raw]
        shown = "an UNLIMITED amount of" if req.unlimited else f"up to {req.amount}"
        summary = f"Allow {short(to)} to spend {shown} {symbol} from this wallet"
    elif req.action == "revoke":
        fn_name, args = "approve", [to, 0]
        summary = f"Revoke {short(to)}'s permission to spend {symbol}"
    else:
        raise ValueError(f"Unknown action: {req.action!r}")

    data = token.encode_abi(fn_name, args=args)
    tx = {"from": Web3.to_checksum_address(from_addr), "to": token.address, "data": data, "value": 0}
    try:
        gas = w3.eth.estimate_gas(tx)
    except Exception:
        gas = FALLBACK_GAS   # simulate() is where failures are reported, not here

    function, decoded = decode(data)
    return TxPlan(chain_id=w3.eth.chain_id, from_addr=tx["from"], to=token.address, value=0,
                  data=data, gas=gas, function=function, args=decoded, summary=summary)


def decode(data: str) -> tuple[str, dict]:
    """Calldata -> ('transfer(address,uint256)', {'to': '0x..', 'value': 123}). Works offline."""
    contract = Web3().eth.contract(abi=ERC20_ABI)
    fn, params = contract.decode_function_input(data)
    return SIGNATURES.get(fn.fn_name, fn.fn_name), dict(params)
