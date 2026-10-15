# Technical documentation: the chain layer (`wallet_engine`)

*Sentinel Wallet · FinTechathon 2026 International Track · Topic F (Agent Wallet)*
*Section owner: Person 1 (chain and wallet engine)*

## 1. Purpose

The chain layer is the part of Sentinel Wallet that touches the blockchain. It answers three
questions truthfully and nothing else:

1. **What does the wallet hold?** (`balances`, `approvals`)
2. **What exactly would this action do?** (`plan`, `simulate`)
3. **Do it, but only with the firewall's valid approval.** (`execute`)

It never decides *whether* an action is allowed. That is the firewall's job (Person 2). The chain layer
only refuses to act without the firewall's proof, and it reports facts about the transaction that the
firewall can rely on.

## 2. Networks and token

| | Local development | Public testnet |
|---|---|---|
| Network | Anvil (Foundry), chain id **31337** | Ethereum **Sepolia**, chain id **11155111** |
| Used for | development, tests, the attack replay | the public, verifiable evidence |
| Node | `http://127.0.0.1:8545` on the developer's computer | Alchemy HTTPS endpoint (`RPC_URL_SEPOLIA`) |
| Money | simulated | free faucet test ETH, no value |
| Test token (TUSD) | `0x5FbDB2315678afecb367f032d93F642f64180aa3` (first deployment on a fresh Anvil) | `0x81EBDCC80E45b57e774e13Ee4725963A872f0f47` |
| Deployment tx | `0x301f7aa0…c10c9` | [`0x0f62eea9…af4a3d`](https://sepolia.etherscan.io/tx/0x0f62eea9a59561bfea4573eabba7b82c6a7cd7686224d83746fdd8f956af4a3d) (block 11916214) |

**Test money only.** No real funds and no Ethereum mainnet are used anywhere in the project.

The token is `contracts/TestUSD.sol`: a plain ERC-20 (name TestUSD, symbol TUSD, **18 decimals**,
1,000,000 minted to the deployer). It has no owner, no mint function and no special permissions.
It was written without dependencies so that it is easy to audit. One property matters to our design:
an allowance of the maximum `uint256` is never reduced by `transferFrom` ("unlimited"), which is
exactly why an unlimited approval is dangerous.

Deployment records are kept in `evidence/deployments.json`.

## 3. Key handling

| Network | Key variable in `.env` | What it is |
|---|---|---|
| local | `WALLET_PRIVATE_KEY` | Anvil's public account #0 (the victim wallet). Identical on every machine; worthless outside the laptop. |
| local | `ATTACKER_PRIVATE_KEY` | Anvil's public account #1, used only by the drainer in the attack replay |
| Sepolia | `SEPOLIA_PRIVATE_KEY` | A freshly generated throwaway key, funded by a faucet; holds no real value |

Rules enforced by the code and the repository:

- Keys live only in `.env`, which is git-ignored and never committed.
- `chain.key_var()` selects the key from `ACTIVE_NETWORK`, so a Sepolia run can never silently use the
  local key and vice versa.
- A key is never logged, printed, returned from a function or sent to the frontend. The LLM API key
  stays on the backend as well.
- A test (`test_never_returns_or_prints_the_key`) checks that a configured key never appears in the drainer's output.

## 4. Components

| File | Responsibility |
|---|---|
| `chain.py` | Connect to the active network; read balances; read active approvals (scans the token's `Approval` events from the deployment block, then reads each current allowance) |
| `erc20.py` | Safe amount conversion (`Decimal` and integers only, no floats); build `transfer`, `approve`, `revoke`; decode calldata |
| `simulate.py` | Dry-run a transaction with `eth_call` and `estimate_gas` |
| `execute.py` | Sign and send, only with a valid approval |
| `binding.py` | Read what a transaction really does from its calldata (the fields an approval token must bind to) |
| `attacks/drainer.py` | The attacker for the attack replay (local chain only) |
| `scripts/deploy.py` | Deploy TestUSD and record it in `evidence/deployments.json` |

The facade (`wallet_engine/__init__.py`) exposes `plan`, `simulate`, `execute`, `balances` and `approvals`.
Their names and argument lists are the shared contract with the firewall and the agent and are guarded by
`tests/test_contract.py`.

## 5. The transaction pipeline

```
ActionRequest ──► plan() ──► TxPlan ──► simulate() ──► SimResult ──► [firewall decides] ──► execute() ──► tx hash
```

### 5.1 `plan(request) → TxPlan`
Builds the exact transaction and sends nothing. Supported actions: `transfer`, `approve` (limited or
unlimited) and `revoke` (an approval of 0). The plan contains the chain id, the from address, the target
contract, the calldata, the gas estimate, a decoded function and arguments, and a plain-English summary
("Send 10 TUSD to 0x7099…79C8"). Amounts are converted with `Decimal` using the token's real decimals.

### 5.2 `simulate(plan) → SimResult`
Asks the node what would happen without sending anything. It checks, in order:

1. the node is reachable and the plan's chain id matches the node;
2. the transaction carries no ETH value (value 0 only);
3. calldata is a supported ERC-20 call;
4. the target address is a contract;
5. `eth_call` succeeds (otherwise the contract's revert reason is returned, e.g. *"TestUSD: insufficient balance"*);
6. `estimate_gas` succeeds and the wallet has enough ETH to pay for gas.

It never raises: a problem is returned as `ok=False` with a readable reason, so the firewall can deny it
(rule SIM-01). The reported `outflow` and `allowance_after` are computed from the **calldata that would be
signed**, not from the request or the plan's description. A plan that lies about itself is therefore
still measured honestly.

### 5.3 `execute(plan, decision) → tx hash`
The only function that sends a transaction. It raises `ExecutionRefused` (nothing is sent) unless **all** of
these hold:

1. the decision is `allow` and carries an approval token;
2. `firewall.tokens.verify_token` accepts the token for the exact transaction that will be signed;
3. the plan is for the connected chain and for **this** wallet, has value 0 and a gas limit between 21,000 and 500,000;
4. a fresh simulation, run immediately before sending, still succeeds.

Then it signs with the key for the active network (EIP-1559 fees when the chain supports them, gas limit +20% capped at 500,000),
sends, waits for the receipt (up to 120 seconds) and raises `ExecutionFailed` if the receipt status is 0.
It writes `EXECUTE_REFUSED` / `TX_SENT` / `TX_FAILED` events to the audit log on a best-effort basis; a
logging error can never block or hide a transaction.

## 6. Why `execute` needs an approval token

An AI agent can be talked into wanting a transaction. The only way to make that harmless is that the
component holding the key refuses to act on anyone's word but the firewall's proof. The token is bound to
**what will actually be signed**, which prevents the classic "approve A, send B" attack:

`binding.token_binding(plan)` reads the calldata and returns four fields:

| Field | Meaning |
|---|---|
| `action` | `transfer`, `approve` or `revoke` (an approve of 0 is a revoke) |
| `token` | the ERC-20 contract the call goes to |
| `to` | recipient (transfer) or spender (approve / revoke) |
| `amount` | the raw on-chain integer as a string (so an unlimited approval is the maximum `uint256`) |

The firewall issues the token for exactly these fields; `execute` re-derives them from the transaction and
calls `verify_token`. If the amount, recipient, token or action differs by a single character, the token is
rejected and nothing is sent. The fields come from the calldata and not from the request text, so editing
the description of a plan cannot make a different transaction pass.

## 7. The attack replay (`attacks/drainer.py`)

The drainer plays the attacker for the demo: with an allowance the victim granted, it calls
`transferFrom(victim, attacker, amount)` signed by the attacker key. It demonstrates why an unlimited
approval is dangerous (it can be reused until revoked) and why the firewall must deny it (rule APR-01).

Hard limits, checked in this order before any transaction is sent:

1. `ACTIVE_NETWORK` must be `local`;
2. the node must be reachable and its chain id must be **31337**, even if `RPC_URL_LOCAL` points elsewhere;
3. `ATTACKER_PRIVATE_KEY` must be set (and is never printed);
4. there must be a real allowance, a valid amount, not above the allowance or the victim's balance.

## 8. Limits and known risks (honest list)

| Item | Limit or risk |
|---|---|
| Scope | ERC-20 `transfer`, `approve` and `revoke` of one token only. **No swaps, no plain ETH transfers, no batching, no `transferFrom` by the wallet.** |
| Test money | Test tokens on Anvil and Sepolia only. Never audited for production or real funds. |
| Simulation | `eth_call` shows the result on the current state. It cannot predict what other transactions do before ours is mined (ordering, front-running). The pre-send re-simulation reduces but does not remove this. |
| Trust in the node | A single RPC provider (Alchemy for Sepolia) answers all reads and receives all transactions. A dishonest node could mislead the simulation. |
| Approval list | Found by scanning `Approval` events from the deployment block, then reading current allowances. Efficient for a demo-sized chain, not for long histories. |
| Single wallet | One signing key per network; no multi-signature or hardware wallet support. |
| Dependency on the firewall | The chain layer is only as safe as `verify_token`. Until Person 2's real HMAC tokens land, the firewall is a stub that accepts a fixed string. |
| Key storage | Keys sit in a local `.env`. Acceptable for test keys; a real deployment would need a managed vault or hardware signer. |

## 9. Testing

`python -m pytest -q` runs **70 tests** with a local Anvil and the token deployed (38 pass and 32 skip
without Anvil, because the live tests skip themselves). Live tests are rolled back with
`evm_snapshot` / `evm_revert` and run on the local chain only.

| Area | What is proven |
|---|---|
| Amounts | Decimal-safe conversion; rejects negatives, junk and too many decimals |
| Calldata / binding | Transfer, approve, revoke and unlimited decode correctly; malformed calldata is rejected |
| Token | Metadata and supply; over-balance reverts; limited approval is consumed; unlimited is never used up; revoke stops it |
| `simulate` | Success; revert reason surfaced; outflow read from calldata; wrong chain, non-contract, ETH value, junk calldata, missing gas money, no node |
| `execute` | Real transfer, approve and revoke; refuses non-allow decisions, missing or mismatched tokens (amount and recipient swaps), wrong wallet or chain, bad gas, failing simulation, no node; nothing is sent on any refusal |
| Drainer | Works with an unlimited allowance and is repeatable; respects limited allowances; refuses with no or revoked allowance, bad amounts, non-local network, wrong chain id, no key; never prints the key |

## 10. Evidence collected so far

| Evidence | Where |
|---|---|
| Token deployments (local and Sepolia) | `evidence/deployments.json` |
| Sepolia deployment | [`0x0f62eea9…af4a3d`](https://sepolia.etherscan.io/tx/0x0f62eea9a59561bfea4573eabba7b82c6a7cd7686224d83746fdd8f956af4a3d) |
| Sepolia transfer of 1 TUSD through `plan → simulate → execute` | [`0x1c886a64…d4599`](https://sepolia.etherscan.io/tx/0x1c886a6470c45f802b952c675fb72951edf69df76eb19f4839d03b2b351d4599) |

The final evidence run (5 or more transactions through the **real** firewall, plus one firewall-denied
action) is tracked in issue #11 and is waiting for the firewall's real rules and tokens (#15, #16).
