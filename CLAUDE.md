# Sundarban (Wallet Firewall): project context for AI assistants

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
- RESOLVED: the organizer confirmed that Sepolia (testnet) transaction hashes are accepted as on-chain execution evidence.
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
The user running this session is **Person 1**. All three roles' code is now built and merged (see Status below).

## The contract (do not rename fields or change signatures)
- Data types: `shared/types.py` (ActionRequest, TxPlan, SimResult, Decision, AgentReply).
- Facade:
  - `wallet_engine`: `plan(req)->TxPlan`, `simulate(plan)->SimResult`, `execute(plan, decision)->tx_hash`, `balances()`, `approvals()`
  - `firewall`: `evaluate(req, plan, sim)->Decision`, `confirm(req, plan)->Decision`, `preview(req, plan, sim)->Decision` (same answer as evaluate, NO side effects; used by the Preview screen), `audit.log(event)`, `audit.verify(path)`, `state.set_kill_switch(bool)`, `tokens.verify_token(...)`
  - `agent`: `handle_message(text, origin="user_chat")->AgentReply`; `agent.naive_agent.handle_message(...)` has NO firewall (local only)
- `tests/test_contract.py` fails if a field or signature changes. Keep it passing.
- Flow: agent -> ActionRequest(origin by code) -> engine.plan -> engine.simulate -> firewall.evaluate -> [ask: UI confirm -> firewall.confirm] -> engine.execute (needs valid approval token) -> audit.

## Firewall rules (Person 2; deny > ask > allow; default deny)
DENY: PRV-01 untrusted origin · KIL-01 kill switch on · NET-01 wrong chain id · TOK-01 not our token contract ·
APR-01 unlimited approval · APR-02 approval to a non-allowlisted spender · ADR-01 look-alike of an allowlisted address ·
DST-01 burn address or the token contract itself · SIM-01 the dry run failed, OR the calldata does not match the request
(action, token, recipient, amount, unlimited flag, native value), OR more tokens leave than requested ·
LIM-01 over max per transaction · LIM-03 over the rolling daily cap (approvals count too) ·
CNF-01 confirm() without an open question for this exact transaction · DEF-01 anything unexpected.
ASK: ALW-01 new recipient · LIM-02 over the auto limit · VEL-01 five or more actions already in the last 10 minutes.
Limits live in `firewall/rules.yaml` (auto 50, max 500, daily 1000 TUSD; `chain_id: null` means NET-01 uses the node's chain).
Full table with enforcement points: `docs/security_self_assessment.md` section 3.2.

## Tech stack
Python 3.14 (the only version tested; 3.11 to 3.13 not verified), web3.py v7, Foundry (anvil, forge), Sepolia testnet, OpenZeppelin ERC-20 "TestUSD",
an OpenAI-compatible LLM API (openai SDK; LLM_BASE_URL / LLM_MODEL / LLM_API_KEY in .env, provider switchable),
PyYAML, HMAC-SHA256 (stdlib), JSONL hash-chained log, FastAPI backend (`api/main.py`, port 8000),
React + Vite frontend (`ui/`, port 5173, proxies /api to 8000), pytest.
DECISION (2026-10-15): UI is FastAPI + React, NOT Streamlit (the role PDFs still say Streamlit; README is authoritative).
Amounts: use Decimal / integers, never float. Read chain id from the node, never hardcode.
web3.py v7 names: `build_transaction`, `sign_transaction`, `signed.raw_transaction` (v6 names differ).

## Environment notes
- This repo lives on an **NTFS drive** (`/run/media/salman/FCB8237BB8233414/wallet`). Keep the Python venv OFF it
  (e.g. `~/.venvs/sentinel`). `core.fileMode` is set to false.
- GitHub: https://github.com/Bijoy2406/Sundarban (**currently private**: make it public, or add the judges, before submitting). `main` is the default branch (also `bijoy`). Issues track the work (labels person1/2/3); the "Build order" issue gives the sequence.

## Status (updated 18 Oct 2026)
Code and evidence are complete; what remains is the presentation material and sending it.
- [x] Shared types and contract test; wallet engine (plan, simulate, execute, binding, pending state); TestUSD on local Anvil and Sepolia
- [x] Firewall: policy engine with 16 rules, strict rules loader, persistent HMAC-chained spend ledger, kill switch, provenance,
      single-use HMAC approval tokens, hash-chained audit log with cross-process locking (Linux, Windows, portable), `preview()`
- [x] Agent (strict intent parser, protected agent, naive agent, synthetic feed, attack replay), FastAPI backend, React UI
- [x] Red-team: 40 attacks + 15 benign cases, runner and report (`python -m firewall.redteam.run`): 55/55, 0/40 attacks let through,
      0/15 wrongly denied; both agents on Anvil: protected executes 0/40, naive executes 38/40
- [x] Sepolia evidence run through the real pipeline: 6 transactions sent, 2 denied (`evidence/tx_hashes.csv`); audit head anchored on Sepolia
- [x] Tests: 1288 passed / 1 skipped with Anvil, 1226 passed / 63 skipped without
- [x] Documents: `README.md`, `docs/technical_overview.md`, `docs/security_self_assessment.md`, `docs/tech_chain_layer.md`
- [ ] Deck (10 minutes at most), demo video (5 minutes at most, no keys on screen), final email: drafts in `docs/presentation_outline.md`,
      `docs/demo_video_script.md`, `docs/submission_package.md`. Issue #28 stays open until these exist.
- [ ] Send the package to wangyr@pbcsf.tsinghua.edu.cn: deadline 20 Oct 2026 23:59 Beijing time, aim for noon; code freeze 19 Oct.
Decisions still open for the team (all documented in the self-assessment risk list): set `chain_id` in `firewall/rules.yaml` so NET-01 is
active (R-01); make the repository public or add the judges; run the suite once on a real Windows machine (R-16). R-09 (broadcast
timeout), R-10 (replay wording on an outage), R-11 (`--verify` on a malformed record) and the Host-header exposure (R-03) are mitigated.

## Changes made outside the author's own folder (to be announced to Person 2 and Person 3)
Rule above: only edit your own folder. On 17-18 Oct 2026 Person 1 (with Person 2 and Person 3 busy) also changed:
- Person 2's `firewall/tokens.py` (a used approval token stays used: canonical expiry, memory keyed by signature) and
  `firewall/policy.py` (VEL-01 wording only); new `shared/redact.py` (error-text redaction, a new file, `shared/types.py` untouched).
- Person 3's `agent/` (replay, `handle_intent`, intent parser, redaction), `api/main.py` (Host allowlist, address checks, token never
  sent to the browser, pending state) and `ui/src/App.jsx` (replay card, pending state).
Each change has tests and is in git history. Person 2 and Person 3 must read them before submission; nothing here changes a rule
threshold, the allowlist, `rules.yaml` or `shared/types.py`.

## Working style
- Small steps, run everything, commit after each working step.
- Learn-first or build-first are both fine; always explain new code in plain words (the team are beginners with web3).
- Reference PDFs (outside the repo, in `~/Downloads/FinTechathon2026/`): Person1/2/3 role PDFs, order-of-work PDF.
