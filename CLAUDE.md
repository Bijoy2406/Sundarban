# Sentinel Wallet (Wallet Firewall): project context for AI assistants

Read this first. It replaces the conversation history that earlier sessions had.

## What this is
A student-competition project: **FinTechathon 2026, International Track, Topic F (Agent Wallet)**.
An AI wallet agent that can really send ERC-20 tokens on-chain, but **cannot be tricked into it**:
a deterministic Firewall (plain Python rules, no AI) decides allow / ask / deny; risky actions need a human
confirm outside the chat; every step goes to a hash-chained audit log.

Why: in May 2026 an encoded public X reply plus a gifted NFT made Grok's auto-provisioned Bankr wallet send
about $150K of tokens (prompt injection + privilege escalation, no key stolen). Our demo replays that attack
against a naive agent (funds lost on a LOCAL chain) and against ours (blocked, with the reason).

## Hard facts
- Deadline: **20 Oct 2026, 23:59 Beijing time (UTC+8)**. Aim to send by noon Beijing time.
- Submit by email to wangyr@pbcsf.tsinghua.edu.cn: technical doc, deck (<=10 min), demo video (<=5 min, optional),
  source code (README, GitHub link, deploy steps, test cases), security self-assessment (permission tiers + known-risk list),
  execution evidence (for the on-chain topic: real on-chain transaction hashes).
- Scoring: task completion 40%, security and compliance 30%, innovation and interaction 30%, plus 0-5 bonus for on-chain.
- OPEN QUESTION: are Sepolia (testnet) hashes accepted as "real on-chain transaction hashes"? Ask the organizer before relying on it.
- Team of 3. English only for all deliverables.

## Safety rules (never break)
- **Test tokens only. Never real money. Never mainnet.** Local Anvil + Sepolia only.
- Never hardcode or print private keys; read from `.env` (gitignored). Never commit `.env`.
- The drainer and the naive agent must refuse to run unless the chain is the local Anvil chain.
- **`origin` of every request is set by CODE from the channel it arrived on, never by the LLM.**
- Only code decides permissions. Text, NFTs or on-chain holdings can never grant privileges.

## Roles, folders, branches
| Person | Role | Owns | Branch |
|---|---|---|---|
| 1 | Chain and wallet engine (web3.py, Anvil, Sepolia evidence) | `wallet_engine/` | `person1-engine` |
| 2 | Firewall and security (rules, tokens, audit, red-team, security report) | `firewall/`, `shared/types.py` | `person2-firewall` |
| 3 | Agent, UI and demo (LLM intents, FastAPI + React UI, README, deck, video) | `agent/`, `api/`, `ui/`, `README.md` | `person3-agent` |

Only edit your own folder. Changes to `shared/types.py` go through Person 2 and are announced to everyone.
The user running this session is **Person 1**. Person 2's startup pieces (types, stubs, config) were scaffolded
by Claude; the real firewall logic is still to be built.

## The contract (do not rename fields or change signatures)
- Data types: `shared/types.py` (ActionRequest, TxPlan, SimResult, Decision, AgentReply).
- Facade:
  - `wallet_engine`: `plan(req)->TxPlan`, `simulate(plan)->SimResult`, `execute(plan, decision)->tx_hash`, `balances()`, `approvals()`
  - `firewall`: `evaluate(req, plan, sim)->Decision`, `confirm(req, plan)->Decision`, `audit.log(event)`, `audit.verify(path)`, `state.set_kill_switch(bool)`, `tokens.verify_token(...)`
  - `agent`: `handle_message(text, origin="user_chat")->AgentReply`; `agent.naive_agent.handle_message(...)` has NO firewall (local only)
- `tests/test_contract.py` fails if a field or signature changes. Keep it passing.
- Flow: agent -> ActionRequest(origin by code) -> engine.plan -> engine.simulate -> firewall.evaluate -> [ask: UI confirm -> firewall.confirm] -> engine.execute (needs valid approval token) -> audit.

## Firewall rules (Person 2 implements; deny > ask > allow; default deny)
PRV-01 untrusted origin: deny · KIL-01 kill switch: deny · NET-01 wrong chain id: deny · APR-01 unlimited approval: deny ·
APR-02 approval to non-allowlisted spender: deny · ADR-01 look-alike of an allowlisted address: deny ·
SIM-01 simulation failed or outflow > requested: deny · LIM-01 over max per-tx: deny · LIM-03 over daily cap: deny ·
ALW-01 new recipient: ask · LIM-02 over auto limit: ask · VEL-01 more than 5 actions in 10 min: ask.
Limits live in `firewall/rules.yaml` (auto 50, max 500, daily 1000 TUSD).

## Tech stack
Python 3.11+, web3.py v7, Foundry (anvil, forge), Sepolia testnet, OpenZeppelin ERC-20 "TestUSD",
an OpenAI-compatible LLM API (openai SDK; LLM_BASE_URL / LLM_MODEL / LLM_API_KEY in .env, provider switchable),
PyYAML, HMAC-SHA256 (stdlib), JSONL hash-chained log, FastAPI backend (`api/main.py`, port 8000),
React + Vite frontend (`ui/`, port 5173, proxies /api to 8000), pytest.
DECISION (2026-10-15): UI is FastAPI + React, NOT Streamlit (the role PDFs still say Streamlit; README is authoritative).
Amounts: use Decimal / integers, never float. Read chain id from the node, never hardcode.
web3.py v7 names: `build_transaction`, `sign_transaction`, `signed.raw_transaction` (v6 names differ).

## Environment notes
- This repo lives on an **NTFS drive** (`/run/media/salman/FCB8237BB8233414/wallet`). Keep the Python venv OFF it
  (e.g. `~/.venvs/sentinel`). `core.fileMode` is set to false.
- GitHub: https://github.com/Bijoy2406/Sentinel-Wallet (public). `main` is the default branch (also `bijoy`). Issues track the work (labels person1/2/3); the "Build order" issue gives the sequence.

## Status (update this section as work lands)
- [x] Skeleton, shared types, stubs, rules.yaml, contract test (3 passing)
- [x] Person 1 (done): Foundry 1.8.5 installed, TestUSD contract written and deployed on local Anvil, 6 on-chain tests pass
- [x] Person 1 (done): chain.py + erc20.py (plan, decode, balances, approvals), tested
- [x] Starter FastAPI + React app (status, wallet, preview, LLM test) and OpenAI-compatible LLM client
- [x] Sepolia: Alchemy RPC set, throwaway wallet funded, TestUSD deployed on Sepolia (evidence/deployments.json)
      Key selection: ACTIVE_NETWORK=local uses WALLET_PRIVATE_KEY; sepolia uses SEPOLIA_PRIVATE_KEY (chain.key_var()).
- [x] Person 1: simulate.py + execute.py done and verified (local Anvil and one real Sepolia tx); binding.py defines what the approval token must bind to
- [x] Person 1: drainer done (wallet_engine/attacks/drainer.py, local chain 31337 only, 17 tests)
- [ ] Person 1 (todo): 5+ Sepolia txs through the full pipeline once the real firewall lands (#11), tech doc section (#12)
- [ ] Person 2: real policy, provenance, HMAC tokens, audit chain, 40 attack + 15 benign cases, security report
- [ ] Person 3: intent parser, feed, agent, naive agent, full UI (decision card, confirm, kill switch, audit, attack replay), deck, video, final package

## Working style
- Small steps, run everything, commit after each working step.
- Learn-first or build-first are both fine; always explain new code in plain words (the team are beginners with web3).
- Reference PDFs (outside the repo, in `~/Downloads/FinTechathon2026/`): Person1/2/3 role PDFs, order-of-work PDF.
