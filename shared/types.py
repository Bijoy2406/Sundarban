# shared/types.py
# The shared contract between Person 1 (wallet_engine), Person 2 (firewall) and Person 3 (agent/ui).
# Do NOT rename fields or change types without telling the whole team first.
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ActionRequest:
    request_id: str
    action: str            # "transfer" | "approve" | "revoke"
    token: str             # ERC-20 contract address (or "ETH")
    to: str                # recipient (transfer) or spender (approve/revoke)
    amount: str            # decimal string in token units, e.g. "12.5"
    unlimited: bool        # True if amount means max uint256
    origin: str            # "user_chat" | "public_feed" | "nft_metadata" | "tool_output"
    rationale: str = ""    # short text from the LLM (for display only)


@dataclass
class TxPlan:
    chain_id: int
    from_addr: str
    to: str                # contract or recipient the tx is sent to
    value: int             # wei
    data: str              # hex calldata
    gas: int
    function: str          # e.g. "transfer(address,uint256)"
    args: dict             # decoded args
    summary: str           # plain English: "Send 10 TUSD to 0xAbc..."


@dataclass
class SimResult:
    ok: bool
    revert_reason: Optional[str]
    outflow: str                     # amount of token that leaves the wallet, token units
    allowance_after: Optional[str]   # for approve: resulting allowance, else None


@dataclass
class Decision:
    request_id: str
    decision: str          # "allow" | "ask" | "deny"
    rule_ids: list = field(default_factory=list)
    reasons: list = field(default_factory=list)   # plain-English strings
    approval_token: Optional[str] = None


@dataclass
class AgentReply:
    text: str
    decision: Optional[Decision] = None
    tx_hash: Optional[str] = None
    blocked: bool = False
