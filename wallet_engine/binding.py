"""What a transaction REALLY does, read from its calldata (Person 1).

The approval token must be tied to the bytes that will actually be signed, not to a
human-readable description. This module turns a TxPlan into four plain fields:

    action  "transfer" | "approve" | "revoke"   (approve with value 0 is a revoke)
    token   the ERC-20 contract the call goes to      (lower-case 0x address)
    to      recipient (transfer) or spender (approve) (lower-case 0x address)
    amount  the raw on-chain integer as a string, e.g. "10000000000000000000"

Both sides must use the same fields:
  * Person 1  execute()  -> firewall.tokens.verify_token(token, request_id, action, token, to, amount)
  * Person 2  confirm()  -> firewall.tokens.issue_token(...)  with  token_binding(plan)

Dependency-free on purpose (no web3 import) so the firewall can use it without cycles.
"""
from shared.types import TxPlan

TRANSFER = "a9059cbb"   # transfer(address,uint256)
APPROVE = "095ea7b3"    # approve(address,uint256)


def token_binding(plan: TxPlan) -> dict:
    """Return {'action','token','to','amount'} derived from plan.data. Raises ValueError if unsupported."""
    data = plan.data
    if not isinstance(data, str) or not data.lower().startswith("0x"):
        raise ValueError("calldata must be a 0x hex string")
    raw = data[2:].lower()
    selector, body = raw[:8], raw[8:]
    if selector not in (TRANSFER, APPROVE):
        raise ValueError(f"unsupported function selector 0x{selector}")
    if len(body) != 128:
        raise ValueError("calldata must contain exactly two 32-byte arguments")
    try:
        address_word, value_word = body[:64], body[64:]
        if int(address_word[:24], 16) != 0:
            raise ValueError("address argument is not a clean 20-byte address")
        recipient = "0x" + address_word[24:]
        int(address_word, 16)
        value = int(value_word, 16)
    except ValueError as exc:
        raise ValueError(f"malformed calldata: {exc}")

    if selector == TRANSFER:
        action = "transfer"
    else:
        action = "revoke" if value == 0 else "approve"
    return {"action": action, "token": str(plan.to).lower(), "to": recipient, "amount": str(value)}
