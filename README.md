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

## Implementation status

The repository now contains the main wallet engine, firewall, agent, API, and React UI components. Feature tests and the end-to-end test file are part of the repository; **test results depend on the environment**. Tests that require Anvil and a deployed TestUSD contract may be skipped when those prerequisites are unavailable. Do not treat skipped tests as proof of a live transaction flow.

| Component | Current implementation |
|---|---|
| Shared contract | `shared/types.py`; guarded by `tests/test_contract.py` |
| TestUSD ERC-20 | Solidity contract and Foundry deploy script; local Anvil and Sepolia configuration are supported |
| Wallet engine | Planning, simulation, transaction execution, balances, approvals and calldata binding |
| Firewall | Deterministic policy evaluation, explicit confirmation, HMAC-bound approval tokens, kill switch and audit logging |
| Agent | Strict intent parsing and protected orchestration; provenance is assigned by trusted code |
| Naive agent + drainer | Intentionally unsafe demo path, restricted to local Anvil chain ID `31337` |
| Backend + UI | FastAPI endpoints and React/Vite wallet, confirmation, audit and attack-replay surfaces |

Check the actual test output from your environment before making claims about coverage. The current full-suite history includes Windows audit-locking failures; see [Testing and known limitations](docs/technical_overview.md#testing-and-known-limitations).

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

The preview uses the transaction planner and simulation result. Execution is handled by the server API, which re-runs plan → simulate → firewall evaluation; the browser cannot authorize a transaction by sending its own decision. An `ask` result requires a separate confirmation action.

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

## 8. The audit log

Every refusal and every sent transaction is appended to `logs/audit.jsonl` (git-ignored; override with
`AUDIT_LOG_PATH`). Each line stores the hash of the previous line, so editing, deleting, inserting or
re-ordering anything breaks the chain. Secrets (keys, approval tokens) are redacted before writing.

```bash
python scripts/verify_audit.py          # OK: N entries, head <hash>   (exit 0)  |  FAILED: ... line N (exit 1)
python scripts/verify_audit.py tail     # newest entries
```
Deleting the *last* entries leaves a valid shorter chain; to detect that, keep the head hash somewhere
else and call `audit.verify(expected_head=...)`.

## 9. The attack drainer (local chain only)

Plays the attacker in the attack replay: once the wallet has granted an allowance, it pulls tokens.
It refuses unless `ACTIVE_NETWORK=local` **and** the node's chain id is 31337.

```python
from wallet_engine.attacks.drainer import drain, DrainRefused
result = drain("25")     # or drain() for "as much as the allowance and balance allow"
```
or from a shell: `python -m wallet_engine.attacks.drainer 25`

## 10. Evidence run (Sepolia transactions)

`wallet_engine/scripts/evidence_run.py` pushes 8 scenarios through the full pipeline (6 legitimate actions,
including one that needs a human confirm, and 2 that must be denied) and records them in
`evidence/tx_hashes.csv`, with the audit log copied to `evidence/audit_<network>.jsonl`.

```bash
python wallet_engine/scripts/evidence_run.py --temp-allowlist --auto-confirm      # rehearsal on local anvil
ACTIVE_NETWORK=sepolia python wallet_engine/scripts/evidence_run.py --yes         # the real run (needs the real firewall, #15)
```
On Sepolia it refuses to send without `--yes`, ends with `RESULT: OK` only if 5+ transactions were sent and
at least one action was denied, and records scripted confirmations as "scripted" in the CSV.

## 11. Documentation and submission materials

- [Technical overview](docs/technical_overview.md): architecture, chain layer, firewall, agent flow and known limitations.
- [Presentation outline (under 10 minutes)](docs/presentation_outline.md): timed slide plan and key messages.
- [Demo video script (under 5 minutes)](docs/demo_video_script.md): shot-by-shot narration and safety checklist.
- [Submission package checklist and email draft](docs/submission_package.md): required attachments, unresolved evidence questions and a ready-to-review email.

These are source documents, not proof that a deck was exported, a video recorded, or an email sent. Final submission evidence must be added by the team before delivery.

## 12. Handy `cast` commands (local chain)

```bash
cast chain-id --rpc-url http://127.0.0.1:8545
cast call 0x5FbDB2315678afecb367f032d93F642f64180aa3 "balanceOf(address)(uint256)" 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --rpc-url http://127.0.0.1:8545
```


## 13. Test-case index

Run from the repository root with the Python environment activated:

```bash
python -m pytest tests/test_contract.py -v
python -m pytest tests/test_api.py -v
python -m pytest tests/test_feed.py -v
python -m pytest tests/test_intents.py -v
python -m pytest tests/test_agent.py -v
python -m pytest tests/test_naive_agent.py -v
python -m pytest tests/test_drainer.py -v
python -m pytest tests/test_policy.py -v
python -m pytest tests/test_simulate_execute.py -v
python -m pytest -q
```

| Test file | Main purpose | Live-chain requirement |
|---|---|---|
| `tests/test_contract.py` | Shared dataclass fields, function signatures and firewall facade contract | No |
| `tests/test_intents.py` | Strict intent schema, retry/refusal and untrusted-text delimiters | No |
| `tests/test_agent.py` | Allow/ask/deny orchestration, confirmation and replay behavior with stubs | No |
| `tests/test_naive_agent.py` | Naive-agent chain guard and deliberately unprotected execution path | Mocked |
| `tests/test_feed.py` | Synthetic feed size, attack categories and trusted origin mapping | No |
| `tests/test_api.py` | API endpoints, server-side decision enforcement and friendly errors | No (mocked) |
| `tests/test_drainer.py` | Local-only drainer guard and behavior | Mocked/local-chain fixtures |
| `tests/test_policy.py` | Deterministic firewall policy decisions | No |
| `tests/test_simulate_execute.py` | Simulation, transaction binding and execution guards | Some tests require local chain |
| `tests/test_audit.py`, `tests/test_audit_locking.py` | Audit integrity and concurrent writer behavior | No; platform-dependent locking |

The attack-replay and five-scenario E2E suites are tracked in the feature branches/issues. Confirm that their PRs are merged into the checkout before invoking those test paths.

A skipped test did not pass; it means its prerequisite was unavailable. The E2E scenarios are not verified until they execute against the required local chain.