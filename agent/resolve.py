"""Turn what the LLM extracted into values the wallet engine can use (shared by BOTH agents).

The intent parser returns the token as the user wrote it ("TUSD") and the recipient as plain text.
The wallet engine needs a contract address and a full 0x address. Doing this in one place keeps the
protected agent and the naive demo agent identical, so the attack replay compares like with like.

Everything raised here is a UserInputError: a problem with the request itself, written in plain
English, safe and useful to show to the person.
"""
from __future__ import annotations

import re

from web3 import Web3

from wallet_engine import chain, erc20

_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


class UserInputError(ValueError):
    """The request can not be turned into a transaction. The message is meant for the user."""


def resolve_token(token: str) -> str:
    """The configured token's contract address for its symbol (or the address itself).

    Never guesses: another symbol is refused, and so is plain ETH (this wallet moves TUSD only).
    """
    if not isinstance(token, str) or not token.strip():
        raise UserInputError("Please say which token to use (TUSD).")
    token = token.strip()
    if token.upper() == "ETH":
        raise UserInputError("This wallet only moves TUSD; plain ETH transfers are not supported.")
    if _ADDRESS.match(token):
        return token
    w3 = chain.get_web3()
    address = chain.token_address()
    symbol = str(erc20.token_contract(w3, address).functions.symbol().call())
    if token.casefold() != symbol.casefold():
        raise UserInputError(f"I don't know the token '{token}'. The only supported token is {symbol} "
                             f"(or its 0x contract address).")
    return address


def require_address(value: str, action: str) -> str:
    """The recipient (transfer) or spender (approve / revoke) must be a full 0x address (42 characters).

    A mixed-case address carries a checksum (EIP-55) that catches typos; if it does not match, the address
    is refused. All-lowercase and all-uppercase addresses have no checksum and are accepted.
    """
    role = "recipient" if action == "transfer" else "spender"
    if not isinstance(value, str) or not _ADDRESS.match(value.strip()):
        raise UserInputError(f"Please give the full 0x address (42 characters) of the {role}; "
                             f"names and shortened addresses are not accepted.")
    address = value.strip()
    digits = address[2:]
    mixed_case = any(c in "abcdef" for c in digits) and any(c in "ABCDEF" for c in digits)
    if mixed_case and not Web3.is_checksum_address(address):
        raise UserInputError(f"The {role} address looks mistyped: its upper and lower case letters do not match "
                             f"the address checksum. Please copy the address again.")
    return address
