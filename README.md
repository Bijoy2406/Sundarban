# Sentinel Wallet

An **AI wallet agent that can send tokens on-chain but cannot be tricked into it.**
Every action passes a deterministic **Firewall** (plain Python rules, no AI) that answers
*allow*, *ask* (a human must confirm) or *deny*. Everything is logged in a tamper-evident audit log.

> FinTechathon 2026 · International Track · Topic F (Agent Wallet).
> **Test tokens only. Never real money. Never mainnet.**

**Why:** in May 2026 an encoded public reply on X plus a gifted NFT made an AI agent's wallet send
about $150K of tokens. No key was stolen; the AI simply trusted text it should not have.
Our demo replays that attack against a naive agent (it loses test funds on a local chain) and
against Sentinel Wallet (blocked, with the reason).

---

## Current status (starting point)

| Part | State |
|---|---|
| Shared types + contract test | ✅ done |
| TestUSD token (ERC-20) + deploy script | ✅ done, tested on local Anvil, **deployed on Sepolia** (`evidence/deployments.json`) |
| `wallet_engine`: `plan`, `balances`, `approvals` | ✅ real (read-only, sends nothing) |
| `wallet_engine/attacks/drainer.py` | ✅ attacker for the attack replay; refuses unless local chain 31337 |
| `wallet_engine`: `simulate`, `execute` | ✅ real: dry-run, then sign + send only with a valid approval token (verified on Anvil and Sepolia) |
| `firewall`: rules, tokens, audit log | 🟡 **stub, always "allow"** (Person 2) |
| `agent`: intent parser, naive agent | 🟡 **stub** (Person 3) |
| LLM client (OpenAI-compatible) + test button | ✅ done |
| FastAPI backend + React frontend | ✅ starter: status, wallet, preview, LLM test |

Track the remaining work in **GitHub Issues** (labels `person1`, `person2`, `person3`).
**Start with the issue called "Build order"**: it lists what to do next, in order.

---

## How it works

```
 user ──► agent (LLM → ActionRequest, origin set by CODE)
             │
             ▼
 wallet_engine.plan ──► TxPlan (the exact tx)  ──► wallet_engine.simulate ──► SimResult
             │
             ▼
 firewall.evaluate ──► allow | ask | deny
             │  ask ──► human clicks Confirm in the UI ──► firewall.confirm
             ▼
 wallet_engine.execute (refuses without a valid approval token) ──► tx hash ──► audit log
```

The golden rule: **permission never comes from text.** Anything the agent reads from outside
(public posts, NFT metadata, tool output) is marked untrusted by code, and the firewall denies
any action it triggers.

---

## Project structure and owners

```
wallet/
├─ shared/types.py      data types everyone uses            (Person 2 owns; announce changes)
├─ wallet_engine/       chain + wallet (web3.py, Foundry)    Person 1
│   ├─ chain.py           connect, balances, approvals (read-only)
│   ├─ erc20.py           amounts, build transfer/approve/revoke, decode calldata
│   ├─ contracts/TestUSD.sol   the test token
│   ├─ scripts/deploy.py       deploys TestUSD, writes evidence/deployments.json
│   ├─ attacks/drainer.py     attacker for the attack replay (LOCAL chain only)
│   └─ foundry.toml
├─ firewall/            rules, approval tokens, audit log    Person 2
│   └─ rules.yaml         limits and allowlist
├─ agent/               LLM client, agent, naive agent       Person 3
│   └─ llm.py             OpenAI-compatible client + connection test
├─ api/main.py          FastAPI backend                      Person 3
├─ ui/                  React (Vite) frontend                Person 3
├─ tests/               pytest (everyone adds tests for their own folder)
├─ evidence/            deployments, tx hashes, red-team results
├─ docs/                technical doc, security report, deck
├─ .env.example         copy to .env (never commit .env)
└─ CLAUDE.md            project context for AI assistants (read it if you use Claude)
```

**Only edit your own folder.** Need a change elsewhere? Ask the owner.

---

## 1. Prerequisites (install once)

| Tool | Version | Check | Install |
|---|---|---|---|
| Python | 3.11+ | `python3 --version` | python.org or your package manager |
| Node.js | 20.19+ or 22.12+ | `node -v` | nodejs.org |
| Foundry (anvil, forge, cast) | latest | `anvil --version` | see below |
| git | any | `git --version` | |

**Install Foundry** (official installer, installs into `~/.foundry`):
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```
If `anvil` is "not found" afterwards, add it to your PATH (use `~/.zshrc` for zsh):
```bash
echo 'export PATH="$PATH:$HOME/.foundry/bin"' >> ~/.bashrc && source ~/.bashrc
```

---

## 2. First-time setup

```bash
git clone https://github.com/Bijoy2406/Sentinel-Wallet.git
cd Sentinel-Wallet

# Python (keep the virtual environment OUTSIDE the repo)
python3 -m venv ~/.venvs/sentinel
source ~/.venvs/sentinel/bin/activate
pip install -r requirements.txt

# Frontend
cd ui && npm install && cd ..

# Compile the test token
cd wallet_engine && forge build && cd ..

# Your private settings
cp .env.example .env
```

### Fill in `.env`

| Variable | What to put | Needed for |
|---|---|---|
| `RPC_URL_LOCAL` | keep `http://127.0.0.1:8545` | everything local |
| `ACTIVE_NETWORK` | `local` (switch to `sepolia` only for evidence runs) | everything |
| `WALLET_PRIVATE_KEY` | Anvil **Account #0** private key (printed when you run `anvil`) | local wallet |
| `SEPOLIA_PRIVATE_KEY` | a fresh throwaway key from `cast wallet new`; used only when `ACTIVE_NETWORK=sepolia` | Sepolia evidence run |
| `ATTACKER_PRIVATE_KEY` | Anvil **Account #1** private key | attack demo |
| `APPROVAL_SECRET` | output of `python3 -c "import secrets; print(secrets.token_hex(32))"` | firewall tokens |
| `TOKEN_ADDRESS` | printed by the deploy script (step 3); locally it is `0x5FbDB2315678afecb367f032d93F642f64180aa3` | wallet |
| `RPC_URL_SEPOLIA` | a free Sepolia RPC URL (Alchemy / Infura / public) | evidence run only |
| `LLM_BASE_URL` | any OpenAI-compatible endpoint, default `https://api.xkiro.com/v1` | LLM |
| `LLM_MODEL` | the model name for that provider | LLM |
| `LLM_API_KEY` | your own key | LLM |

Anvil's keys are **public test keys**, identical on every computer, worthless outside your laptop.
Never put a key that holds real money in this project. **Each person keeps their own `.env`;
never commit it, never paste keys into chats or screenshots.**

To switch LLM provider, change only `LLM_BASE_URL`, `LLM_MODEL` and `LLM_API_KEY`.

---

## 3. Run it (4 terminals)

Activate the Python environment in every terminal you use for Python:
`source ~/.venvs/sentinel/bin/activate`

**Terminal 1: local blockchain** (leave it running)
```bash
anvil
```

**Terminal 2: deploy the test token** (again every time you restart anvil, because anvil starts empty)
```bash
python wallet_engine/scripts/deploy.py
```
Expected: `TestUSD deployed on local (chain id 31337)` and token address `0x5FbDB2315678afecb367f032d93F642f64180aa3`.

**Terminal 3: backend** (from the repo root)
```bash
uvicorn api.main:app --reload --port 8000
```
API docs: http://127.0.0.1:8000/docs

**Terminal 4: frontend**
```bash
cd ui && npm run dev
```
Open **http://localhost:5173**

---

## 4. Check that it works

**Backend health:**
```bash
curl http://127.0.0.1:8000/api/health
```
Expected: `"backend":"ok"`, `"connected":true`, `"chain_id":31337`, `"token_deployed":true`.

**In the browser (http://localhost:5173):**

| What you see | Means |
|---|---|
| ✓ Backend, ✓ Chain: local (31337), ✓ TestUSD deployed | backend, anvil and token are fine |
| ✗ LLM configured | normal until you fill `LLM_MODEL` and `LLM_API_KEY` |
| Wallet card: ETH ≈ 10000, TUSD 1000000 | balances are read live from the chain |
| **Preview** (transfer 10 to the prefilled address) | shows "Send 10 TUSD to 0x7099...79C8", `transfer(address,uint256)`, real calldata, a gas estimate, and a green **ALLOW** card tagged **STUB** |
| **Test connection** | with LLM settings filled: "✓ <model> replied OK in … ms" |

The preview now shows the **real simulation** (e.g. a transfer larger than your balance shows "would fail: TestUSD: insufficient balance").
Nothing is sent from the UI yet: the **Execute** button waits for the execute API endpoint (issue #29).

**Tests:**
```bash
python -m pytest -q
```
With anvil running and the token deployed: **all pass**. Without anvil: the chain tests are
**skipped** (shown as `s`), the rest pass. A failure in `tests/test_contract.py` means someone
changed the shared data types or function signatures.

---

## 5. Team workflow

- Branches: `main` (always working, default) · `person1-engine` · `person2-firewall` · `person3-agent`
- Every session: `git pull origin main --rebase`, work, test, commit small, push your branch.
- Share work through a **Pull Request into `main`**; one teammate looks at it before merging.
- Pick up work from **GitHub Issues**: filter by your label (`person1` / `person2` / `person3`).
  Close the issue in the PR description with `Closes #<number>`.
- Never edit `shared/types.py` alone. `tests/test_contract.py` must keep passing.

## 6. Safety rules

1. Local Anvil and Sepolia testnet only. Never mainnet, never real money.
2. `.env` is never committed. Keys never appear in code, chats, screenshots or the UI.
3. The request `origin` is set by code, never by the LLM.
4. The drainer and the naive agent run on the local chain only.

## 7. Troubleshooting

| Problem | Fix |
|---|---|
| `anvil: command not found` | add `~/.foundry/bin` to PATH (see Prerequisites) |
| `ModuleNotFoundError` (shared, api, …) | run commands from the repo root with the venv active |
| UI says "Backend not reachable" | start Terminal 3 (uvicorn on port 8000) |
| ✗ Chain / ✗ TestUSD deployed | start anvil, then run the deploy script again |
| Wallet card error after restarting anvil | anvil starts empty: run the deploy script again |
| Port already in use | stop the old process, or change the port (`--port 8001`; also update `ui/vite.config.js`) |
| LLM test fails | check the 3 `LLM_*` values in `.env`, then restart uvicorn |

## 8. The attack drainer (local chain only)

Plays the attacker in the attack replay: once the wallet has granted an allowance, it pulls tokens.
It refuses unless `ACTIVE_NETWORK=local` **and** the node's chain id is 31337.

```python
from wallet_engine.attacks.drainer import drain, DrainRefused
result = drain("25")     # or drain() for "as much as the allowance and balance allow"
```
or from a shell: `python -m wallet_engine.attacks.drainer 25`

## 9. Handy `cast` commands (local chain)

```bash
cast chain-id --rpc-url http://127.0.0.1:8545
cast call 0x5FbDB2315678afecb367f032d93F642f64180aa3 "balanceOf(address)(uint256)" 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --rpc-url http://127.0.0.1:8545
```
