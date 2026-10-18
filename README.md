# Sundarban

An **AI wallet agent that can send tokens on-chain but cannot be tricked into it.**
Every action passes a deterministic **Firewall** (plain Python rules, no AI) that answers
*allow*, *ask* (a human must confirm) or *deny*. Everything is logged in a tamper-evident audit log.

> FinTechathon 2026 · International Track · Topic F (Agent Wallet).
> **Test tokens only. Never real money. Never mainnet.**

**Why:** in May 2026 an encoded public reply on X plus a gifted NFT made an AI agent's wallet send
about $150K of tokens. No key was stolen; the AI simply trusted text it should not have.
Our demo replays that attack against a naive agent (it loses test funds on a local chain) and
against Sundarban (blocked, with the reason).

**The name.** Like the Sundarbans mangrove forest absorbs the storm before it reaches the land, our firewall
absorbs the attack before it reaches the funds.

**The result in three lines**

1. The same 40 attacks, sent to two agents on a local chain: the naive agent executes **38**, Sundarban executes **0**.
2. In the red-team suite the firewall denies 36 outright, holds 4 for a human and lets **0 of 40** through, while
   wrongly blocking **0 of 15** legitimate requests.
3. **6 real Sepolia transactions** went through the full pipeline (2 more were denied), and the audit log's head hash
   is anchored on Sepolia, so a rewrite or cut-off of that log is detectable.

| Read next | |
|---|---|
| [Technical documentation](docs/technical_overview.md) | architecture, the decision algorithm, security design, how to run it |
| [Security self-assessment](docs/security_self_assessment.md) ([PDF](docs/security_self_assessment.pdf)) | permission tiers, every rule and threshold, OWASP mapping, known risks and what is not solved |
| [Chain layer](docs/tech_chain_layer.md) | how transactions are planned, simulated and sent |

## Evidence at a glance

| Evidence | Result | Reproduce |
|---|---|---|
| Automated tests (local Anvil + TestUSD) | **1357 passed, 1 skipped** | `python -m pytest -q` |
| Automated tests (no chain) | 1293 passed, 65 skipped (skipped is not passed) | `python -m pytest -q` |
| Red-team suite (40 attacks, 15 legitimate) | 55/55 as expected; 36 denied, 4 held, **0 let through**; **0/15** wrongly denied | `python -m firewall.redteam.run --no-write` |
| Same attacks through both real agents | protected agent executed **0/40**; naive agent executed **38/40** | `python -m firewall.redteam.run --agents --no-write` |
| Sepolia transactions through the full pipeline | 6 sent, 2 denied | `evidence/tx_hashes.csv`; the wallet's complete history of 15 sends: [security self-assessment 7.4](docs/security_self_assessment.md#74-sepolia-wallet-activity-complete-list) |
| Audit log of that run | 16 entries, chain intact | `python scripts/verify_audit.py evidence/audit_sepolia.jsonl` |
| Audit head anchored on Sepolia | `RESULT: OK` | `ACTIVE_NETWORK=sepolia python wallet_engine/scripts/anchor_audit.py --verify` (read-only) |

The six Sepolia transactions (wallet `0xB89C8A9826cac01E3b4A01873Bd0C27553567609`, TestUSD `0x81EBDCC80E45b57e774e13Ee4725963A872f0f47`):

| # | Action | Firewall | Transaction |
|---|---|---|---|
| 1 | transfer 10 TUSD to Alice | allow | [`0xd618054f…ee1eef`](https://sepolia.etherscan.io/tx/0xd618054f5ef685458def4764e770906e3b9af71b3d987c737783bbf8e2ee1eef) |
| 2 | transfer 30 TUSD to Bob | allow | [`0xc9e0d856…d5db74`](https://sepolia.etherscan.io/tx/0xc9e0d85681c3578e4fb10455e7b7b21c99d04703b6abaf3e644d3af1bbd5db74) |
| 3 | approve 20 TUSD for Alice | allow | [`0x852eeff0…08d7d0`](https://sepolia.etherscan.io/tx/0x852eeff047f32dd53d8d00d16e4319168f955384aa0f524ed031a930ff08d7d0) |
| 4 | revoke Alice | allow | [`0xbc8af874…9c7000`](https://sepolia.etherscan.io/tx/0xbc8af8740cc5546fe9b88a4bffb3e8e38300d7fde4a4f6ad0aa6748e0d9c7000) |
| 5 | transfer 200 TUSD to Bob | ask (LIM-02), person confirmed | [`0x148f154e…47068f0bc`](https://sepolia.etherscan.io/tx/0x148f154eb921fa0d5eb24b1460241dd67f8e3d9d9a1c2b6824342ed47068f0bc) |
| 6 | transfer 1 TUSD to Alice | ask (VEL-01), person confirmed | [`0x0ee5931f…7560dfc9`](https://sepolia.etherscan.io/tx/0x0ee5931f3bc4d7696ecca703c81dcc1b47fe0a5b2febeb341a4188e57560dfc9) |

The two denied actions (an unlimited approval, and an instruction that came from a public post) have no transaction by
design. The audit-head anchor is
[`0xf21f8ed7…61ccf7`](https://sepolia.etherscan.io/tx/0xf21f8ed702635320a4d1ea57a44cbd6073a9c176cea2147de61a70b36061ccf7).

## Components

| Component | What it is |
|---|---|
| Shared contract | `shared/types.py`; guarded by `tests/test_contract.py` |
| TestUSD ERC-20 | Solidity contract and Foundry deploy script; local Anvil and Sepolia |
| Wallet engine | Planning, simulation, transaction execution, balances, approvals and calldata binding |
| Firewall | Deterministic policy (16 rules), explicit confirmation, HMAC-bound single-use approval tokens, kill switch, persistent spend ledger, hash-chained audit log |
| Agent | Strict intent parsing and protected orchestration; provenance is assigned by trusted code |
| Naive agent + drainer + replay | Intentionally unsafe demo path, restricted to local Anvil chain id `31337` |
| Backend + UI | FastAPI endpoints and React/Vite wallet, confirmation, audit and attack-replay screens |

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
| Python | **3.14 (the only version tested)**; 3.11 to 3.13 are expected to work but were *not verified* | `python3 --version` | python.org or your package manager |
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
git clone https://github.com/Bijoy2406/Sundarban.git
cd Sundarban

# Python (keep the virtual environment OUTSIDE the repo)
python3 -m venv ~/.venvs/sundarban
source ~/.venvs/sundarban/bin/activate
pip install -r requirements.lock      # the exact versions the tests were run with (Python 3.14.4); requirements.txt holds loose bounds

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
| `ATTACKER_PRIVATE_KEY` | Anvil **Account #3** private key (not #1 or #2: those are Alice and Bob on the allowlist, and the attacker must not be a trusted contact) | attack demo |
| `APPROVAL_SECRET` | output of `python3 -c "import secrets; print(secrets.token_hex(32))"` | firewall tokens |
| `OPERATOR_TOKEN` | another random value, at least 16 characters: `python3 -c "import secrets; print(secrets.token_hex(32))"`. Keep it to yourself: it is the key a person types into the UI's **Operator key** field to Confirm an action or to switch the kill switch OFF | Confirm, kill switch OFF |
| `TOKEN_ADDRESS` | printed by the deploy script (step 3); locally it is `0x5FbDB2315678afecb367f032d93F642f64180aa3` | wallet |
| `RPC_URL_SEPOLIA` | a free Sepolia RPC URL (Alchemy / Infura / public) | evidence run only |
| `LLM_BASE_URL` | any OpenAI-compatible endpoint, default `https://api.xkiro.com/v1` | LLM |
| `LLM_MODEL` | the model name for that provider | LLM |
| `LLM_API_KEY` | your own key | LLM |

Anvil's keys are **public test keys**, identical on every computer, worthless outside your laptop.
Never put a key that holds real money in this project. **Each person keeps their own `.env`;
never commit it, never paste keys into chats or screenshots.**

To switch LLM provider, change only `LLM_BASE_URL`, `LLM_MODEL` and `LLM_API_KEY`.

### What works without an LLM key

| Works with no `LLM_*` in `.env` | Needs `LLM_BASE_URL`, `LLM_MODEL` and `LLM_API_KEY` |
|---|---|
| The Preview / Execute / Confirm forms (the firewall, the engine and the audit log do not use a model) | `POST /api/chat` (the chat box: the model turns your sentence into an action) |
| The attack replay: it uses the scripted "fooled model" action and its layer 1 shows "not tested: the model could not be reached" | Replay layer 1 ("did the model refuse?") and the replay using the **real model's** extraction |
| `python -m pytest -q` (the model is replaced in the tests) | |
| `python -m firewall.redteam.run`, with or without `--agents` (fixed intents replace the model) | |
| Evidence checks: `python scripts/verify_audit.py evidence/audit_sepolia.jsonl` (the Sepolia anchor check also needs a Sepolia RPC URL) | |

---

## 3. Run it (4 terminals)

Activate the Python environment in every terminal you use for Python:
`source ~/.venvs/sundarban/bin/activate`

**Terminal 1: local blockchain** (leave it running)
```bash
anvil
```

**Terminal 2: deploy the test token** (again every time you restart anvil, because anvil starts empty)
```bash
python wallet_engine/scripts/deploy.py
```
Expected: `TestUSD deployed on local (chain id 31337)` and token address `0x5FbDB2315678afecb367f032d93F642f64180aa3`.

> **Now copy the printed token address into `.env`** as `TOKEN_ADDRESS=<address>` (the table in step 2 shows it), **before you start
> the backend or run any test**: the firewall only allows this one token, and everything that follows needs it. On a fresh Anvil
> the address is always the one above.

**Terminal 3: backend** (from the repo root)
```bash
uvicorn api.main:app --reload --port 8000
```
API docs: http://127.0.0.1:8000/docs

**Terminal 4: frontend**
```bash
cd ui && npm run dev
```
Open **http://localhost:5173**. Paste your `OPERATOR_TOKEN` into the **Operator key** field at the top of the page: Confirm and
"kill switch OFF" refuse to work without it (turning the kill switch ON never needs it).

> **The attack replay and `python -m firewall.redteam.run --agents` need a fresh chain after any attack you ran by hand.**
> The replay rolls itself back, but a manual drain or approval does not: stop Anvil (`Ctrl+C` in Terminal 1), start it again and
> redeploy the token (Terminal 2). The red-team runner checks this and stops with a clear message if the wallet is not fresh.

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
| **Preview** (transfer 10 to the prefilled address, which is Alice) | shows "Send 10 TUSD to 0x7099...79C8", `transfer(address,uint256)`, real calldata, a gas estimate, and the firewall decision: a green **ALLOW** (Alice is on the allowlist in `firewall/rules.yaml`); an address that is not on the allowlist gives an amber **ASK** |
| **Test connection** | with LLM settings filled: "✓ <model> replied OK in … ms" |

Preview calls `firewall.preview`, which has **no side effects** (it is not counted, records no spending and issues no token), so previewing can never change a later decision. **Execute** is handled by the server, which re-runs plan → simulate → firewall evaluation; the browser cannot authorize a transaction by sending its own decision. An `ask` result needs a separate **Confirm** click.

**Tests:**
```bash
python -m pytest -q
```
With anvil running and the token deployed: **1357 passed, 1 skipped** (the one skip is a retired check that applied only to an older firewall). Without anvil: **1293 passed, 65 skipped** (the chain tests are skipped, shown as `s`, and a skipped test did not pass).
A failure in `tests/test_contract.py` means someone changed the shared data types or function signatures.

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
| ✗ Chain / ✗ TestUSD deployed | start anvil, then run the deploy script again, then check `TOKEN_ADDRESS` in `.env` |
| Red-team `--agents` says "not in its fresh state" | an attack was run by hand: restart Anvil and redeploy the token |
| Confirm or kill-switch OFF answers "Operator key missing or wrong" (403) or "Operator protection is not configured" (503) | set `OPERATOR_TOKEN` in `.env` (16+ characters), restart uvicorn, paste the same value into the UI's Operator key field |
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
else and call `audit.verify(expected_head=...)`. What the log proves and what it does not is in the
[security self-assessment](docs/security_self_assessment.md#5-controls-beyond-the-rules).

**Anchored on Sepolia.** The head hash of the submitted evidence log is also written into a Sepolia
transaction (a zero-value self-transaction whose data is `sundarban-audit-v1:` + the 32-byte head), so a
rewrite or a cut-off of the log is detectable by anyone, using the chain's timestamp:

```bash
ACTIVE_NETWORK=sepolia python wallet_engine/scripts/anchor_audit.py --verify    # read-only, any Sepolia RPC
```
The record is `evidence/audit_anchor_sepolia.json` (transaction
[`0xf21f8ed7…ccf7`](https://sepolia.etherscan.io/tx/0xf21f8ed702635320a4d1ea57a44cbd6073a9c176cea2147de61a70b36061ccf7)).
It proves the log existed in exactly this form at that block; it does not prove the entries are true, and it is
run by hand (`--yes`), not automatically.

## 9. The attack drainer (local chain only)

Plays the attacker in the attack replay: once the wallet has granted an allowance, it pulls tokens.
It refuses unless `ACTIVE_NETWORK=local` **and** the node's chain id is 31337.

```python
from wallet_engine.attacks.drainer import drain, DrainRefused
result = drain("25")     # or drain() for "as much as the allowance and balance allow"
```
or from a shell: `python -m wallet_engine.attacks.drainer 25`

### How the replay page works (`agent/replay.py`)

One attack, **one extracted action, two agents**. The page does not leave the outcome to whatever the language
model happens to do that day:

1. *Layer 1, informational:* the protected agent's own way of reading outside text (an untrusted wrapper
   around it) is tried, and the page reports whether the model refused or still extracted an action.
2. The "fooled model" is the worst case: the same text read **without** the wrapper. If the real model extracts
   an action that pays the attacker, that is used (`source: llm`). Otherwise (refusal, bad reply, no API key,
   another recipient) the action a fooled model would produce comes from a fixed script (`source: scripted`).
   The page labels which one it was.
3. Both agents receive that same action with the same code-assigned origin. The naive agent signs it with no
   firewall and loses the test funds; the protected agent asks the firewall, which answers from the origin
   assigned by code (PRV-01) and the transaction itself (APR-01, ...), never from the text.

The payload shown is the feed text with only its placeholder addresses pointed at the local attacker account;
nothing is added to the attack.

## 10. Evidence run (Sepolia transactions)

`wallet_engine/scripts/evidence_run.py` pushes 8 scenarios through the full pipeline (6 legitimate actions,
including one that needs a human confirm, and 2 that must be denied) and records them in
`evidence/tx_hashes.csv`, with the audit log copied to `evidence/audit_<network>.jsonl`.

```bash
# rehearsal on local anvil: write to scratch files so the submitted evidence/ files stay untouched
AUDIT_LOG_PATH=/tmp/rehearsal_audit.jsonl python wallet_engine/scripts/evidence_run.py --temp-allowlist --auto-confirm --csv /tmp/rehearsal_tx.csv
# the real run: sends real Sepolia transactions and APPENDS to evidence/tx_hashes.csv
ACTIVE_NETWORK=sepolia python wallet_engine/scripts/evidence_run.py --yes
```
On Sepolia it refuses to send without `--yes`, ends with `RESULT: OK` only if 5+ transactions were sent and
at least one action was denied, and records scripted confirmations as "scripted" in the CSV. The submitted run
(`evidence/tx_hashes.csv`) is already recorded; do not run the Sepolia command again unless you intend to spend testnet gas and add rows to that file. Its sixth
scenario is *expected* to be asked (VEL-01, the sixth action within 10 minutes), and the denied rows also list
VEL-01 because requests from the owner's chat count towards the velocity limit (the submitted run was made before the hardening that makes only trusted-origin requests count, so its public-post row lists VEL-01 too; today's firewall would not).

## 11. Documentation and submission materials

- [Technical documentation](docs/technical_overview.md): system architecture, the decision algorithm, security design, API, how to run it.
- [Security self-assessment](docs/security_self_assessment.md): permission tiers, every firewall rule with its threshold, trust boundaries, OWASP LLM/Agentic mapping, the known-risk list and what is not solved.
- [Chain layer](docs/tech_chain_layer.md): how transactions are planned, simulated and sent, and why `execute` needs an approval token.
- [Presentation outline (under 10 minutes)](docs/presentation_outline.md): timed slide plan and key messages.
- [Demo video script (under 5 minutes)](docs/demo_video_script.md): shot-by-shot narration and safety checklist.
- [Submission package checklist and email draft](docs/submission_package.md): required attachments, unresolved evidence questions and a ready-to-review email.

These are source documents, not proof that a deck was exported, a video recorded, or an email sent. Final submission evidence must be added by the team before delivery.

## 12. License and third-party components

Sundarban is released under the [MIT License](LICENSE). It builds on open-source components under their own
licenses: web3.py, FastAPI, PyYAML, python-dotenv and React and Vite (MIT), uvicorn, httpx (BSD), the `openai`
Python client (Apache-2.0) and Foundry (MIT / Apache-2.0). The language model is any OpenAI-compatible provider
you configure; no model weights or provider code are included.

## 13. Handy `cast` commands (local chain)

```bash
cast chain-id --rpc-url http://127.0.0.1:8545
cast call 0x5FbDB2315678afecb367f032d93F642f64180aa3 "balanceOf(address)(uint256)" 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --rpc-url http://127.0.0.1:8545
```

## 14. Test cases

Run all of them (from the repository root, Python environment active):

```bash
python -m pytest -q
```

| Situation | Result (measured 18 Oct 2026) |
|---|---|
| anvil running, token deployed | **1357 passed, 1 skipped** (a retired check in `test_evidence_run.py`) |
| no anvil | **1293 passed, 65 skipped**: the 65 tests that need the local chain show as `s` |

A skipped test did not pass; it means its prerequisite was unavailable. The counts grow as tests are added;
`python -m pytest --collect-only -q | tail -1` gives the current total. Every live test uses the **local** chain only and
is rolled back afterwards (`evm_snapshot` / `evm_revert`), so the wallet is unchanged when the tests finish.
`tests/test_contract.py` fails if anyone changes a shared field or function signature.

### Which test file proves what

**Firewall** (`firewall/`, Person 2)

| Test file | Tests | Skipped without anvil | What it proves |
|---|---|---|---|
| `tests/test_policy_preview.py` | 268 | 0 | The policy engine (issue #15) and the main policy suite despite its name. Every rule fires when it should and only then; deny beats ask beats allow; reasons are plain English; an approval token is tied to the exact transaction; a confirmation works only after an ask, only once, and never overrides a deny; any crash or odd input ends in deny. |
| `tests/test_policy.py` | 71 | 0 | An earlier, smaller version of the same suite; every one of its test names is also in `test_policy_preview.py`. |
| `tests/test_preview_redteam.py` | 71 | 0 | `firewall.preview` has no side effects (no velocity count, no spend, no token, no open question, no audit entry), and on the 53 red-team cases that contain an action it leaves no trace and gives the same answer as `evaluate`. |
| `tests/test_provenance.py` | 90 | 0 | Only `user_chat` is trusted (PRV-01). Every other origin, look-alike name, odd type or broken rules file is denied, and reasons never repeat outside text. |
| `tests/test_state.py` | 294 | 0 | The firewall's memory (issue #13): the strict `rules.yaml` loader, exact 24-hour spending in a tamper-evident ledger, the velocity count, and the kill switch (survives a restart, fails safe), also under parallel use. |
| `tests/test_tokens.py` | 22 | 0 | HMAC approval tokens (issue #16). A valid token passes; a wrong amount, recipient, action, token contract or request id, and an expired, tampered or foreign-secret token all fail. |
| `tests/test_tokens_hardening.py` | 7 | 0 | A token works once; a failed check does not use it up; the kill switch cancels tokens that were already issued. |
| `tests/test_persistence.py` | 32 | 0 | Spent approval tokens and the velocity window live in small files and survive a restart (also a real second process); an unreadable token file refuses every token, an unreadable velocity file means *ask*; the real `logs/` folder is never touched by a test or the red-team runner. |
| `tests/test_audit.py` | 29 | 0 | The hash-chained audit log (issue #17). Editing, deleting, inserting, re-ordering or duplicating a line is detected; secrets are redacted; threads and processes can share one log. |
| `tests/test_audit_locking.py` | 8 | 0 | The audit log stays intact when several processes write at once, including on the Windows path and on drives without `flock` (those code paths are forced on Linux). |
| `tests/test_anchor_audit.py` | 40 | 7 | Anchoring the audit head on a chain and verifying it; a cut-off, rewritten or forged log is caught. |

**Red-team** (`firewall/redteam/`, Person 2)

| Test file | Tests | Skipped without anvil | What it proves |
|---|---|---|---|
| `tests/test_redteam_data.py` | 18 | 0 | The 55 cases are well formed, and a small reference model of the rule table agrees with every expected answer, so the data cannot quietly contradict the rules. |
| `tests/test_redteam_runner.py` | 38 | 2 | The runner reports 55/55 on the real firewall; it notices a firewall that allows everything, one that denies everything, a removed rule and a changed limit; cases stay isolated; it refuses any chain but the local one. The live test sends the same attacks to both agents on anvil. |

**Wallet engine** (`wallet_engine/`, Person 1)

| Test file | Tests | Skipped without anvil | What it proves |
|---|---|---|---|
| `tests/test_erc20.py` | 44 | 4 | Amount conversion both ways; building transfer, approve, unlimited approve and revoke transactions; decoding calldata; reading balances and allowances. |
| `tests/test_chain_approvals_fallback.py` | 18 | 0 | On a public network whose RPC refuses wide log searches, `approvals()` falls back to the known spenders; on the local chain it never does. |
| `tests/test_simulate_execute.py` | 27 | 10 | The dry run (`simulate`) and the sender (`execute`). What a token must bind to; `execute` refuses anything without a matching approval token; a plan cannot be swapped after approval; the live tests send real test transactions. |
| `tests/test_execute_pending.py` | 21 | 0 | A broadcast transaction without a receipt is reported *pending*, not failed; two sends never share a nonce (fake node). |
| `tests/test_redact.py` | 12 | 0 | Error text never shows an RPC URL, an API key or a private key. |
| `tests/test_testusd_local.py` | 6 | 6 | TestUSD behaves like a standard ERC-20: transfers, limited and unlimited approvals (unlimited is never used up), revoke. |
| `tests/test_drainer.py` | 17 | 12 | The attacker script refuses any chain but local 31337 and never shows its key. Against a naive wallet it drains what a granted allowance allows, and revoking stops it. |
| `tests/test_evidence_run.py` | 16 | 4 (3 run + 1 retired) | The Sepolia evidence script: refuses to send without `--yes`, covers the scenarios the issue asks for, expects the sixth action to be asked (VEL-01), writes an audit trail that verifies, and fails the run if a decision is wrong. |

**Agents and API** (`agent/`, `api/`, Person 3)

| Test file | Tests | Skipped without anvil | What it proves |
|---|---|---|---|
| `tests/test_agent.py` | 11 | 0 | The protected agent's pipeline with stand-ins: an allowed request is sent, an ask waits for a confirmation that cannot be replayed, a denied request never executes, a parse failure gets a polite answer. |
| `tests/test_intents.py` | 33 | 0 | Messages become strict intent JSON (fake model): invalid output is retried once, then refused; untrusted text is fenced in and cannot close its wrapper. |
| `tests/test_feed.py` | 7 | 0 | The synthetic public posts and NFT metadata (3 harmless, 6 attacks): their origin is set by code and cannot be influenced by their text. |
| `tests/test_resolve.py` | 25 | 0 | Token symbol to contract address, and 0x-address checks (a mistyped checksum is caught), shared by both agents. |
| `tests/test_naive_agent.py` | 3 | 0 | The deliberately unsafe agent refuses any chain but local 31337 and, with no firewall, executes what the model extracted. |
| `tests/test_api.py` | 15 | 0 | The HTTP backend with stand-ins: execute sends only on allow; an ask needs a separate confirm; a decision sent by the browser is ignored; a replayed confirm is rejected; the LLM key is never returned. |
| `tests/test_api_operator.py` | 17 | 0 | The operator key: Confirm and kill-switch OFF need `X-Operator-Token`; missing and wrong get one 403 text; an unset or short token answers 503; kill switch ON stays open; the key never appears in a response or log. |
| `tests/test_api_address_check.py` | 15 | 0 | The API forms apply the chat agent's full-address and EIP-55 checks (a wrong mixed-case checksum is a 400). |
| `tests/test_api_host_check.py` | 13 | 0 | Only the Host names `localhost` and `127.0.0.1` are served, so a web page using DNS rebinding cannot call the API as the owner. |
| `tests/test_api_token_hidden.py` | 4 | 0 | The approval token is never sent to the browser (execute, confirm, chat). |
| `tests/test_secret_leaks.py` | 6 | 0 | A broken RPC URL (it carries the API key) never reaches an API error, a chat reply or the evidence CSV. |
| `tests/test_attack_replay.py` | 39 | 2 | The attack replay: one extracted action goes to both agents, real model or script (labelled), local-only guard. |
| `tests/test_live_agents_api.py` | 13 | 13 | Both agents and the API against the real firewall and a real local chain. The same text is allowed from the chat and denied from a public post; an unlimited approval is denied; Preview changes nothing; a naive wallet is drained after it signs an unlimited approval. |
| `tests/test_e2e.py` | 5 | 5 | The five protected-agent scenarios on local Anvil (allow, ask then confirm once, PRV-01, APR-01, KIL-01). |
| `tests/test_contract.py` | 3 | 0 | The shared contract: the data types keep their fields and every facade function keeps its signature. |

### Rule by rule: where each firewall rule is proved

The red-team cases are in `firewall/redteam/attacks.jsonl` (`atk-`) and `benign.jsonl` (`ben-`); the column lists the
cases whose reported rules include that rule (from `evidence/redteam_report.md`). "Unit tests" are in
`tests/test_policy_preview.py` unless another file is named.

| Rule | Decision | What it stops | Unit tests | Red-team cases |
|---|---|---|---|---|
| PRV-01 | deny | any action triggered by text from outside the owner's own chat (public posts, NFT metadata, tool output) | `test_provenance.py` | atk-005..014, atk-017 |
| KIL-01 | deny | everything while the emergency stop is on | `kil01_*`, `test_state.py` (kill switch), `test_tokens_hardening.py` | atk-034, atk-035 |
| NET-01 | deny | a transaction for the wrong network, or when the network cannot be confirmed | `net01_*` | atk-027, atk-028 |
| TOK-01 | deny | moving any token other than TestUSD | `tok01_*` | unit tests only |
| DST-01 | deny | sending to a burn address or to the token contract itself | `dst01_*` | unit tests only |
| APR-01 | deny | an unlimited approval | `apr01_*`, `test_live_agents_api.py` | atk-003, atk-014, atk-016, atk-018..020 |
| APR-02 | deny | an approval for a spender that is not on the allowlist | `apr02_*` | atk-003, atk-010, atk-014, atk-021..023 |
| ADR-01 | deny | an address that looks like an allowlisted one (same first and last 6 digits) but is different | `adr01_*` | atk-024..026 |
| SIM-01 | deny | a failed dry run, or a real transaction that differs from the request (recipient, amount, token, native coin), or more tokens leaving than asked | `sim01_*` | unit tests only |
| LIM-01 | deny | a transfer or approval above the per-transaction maximum | `lim01_*` | atk-001, atk-002, atk-011, atk-012, atk-015, atk-036..038 |
| LIM-03 | deny | passing the daily cap in 24 hours (approvals count too) | `lim03_*`, `test_state.py` (24-hour window, ledger) | atk-001, atk-012, atk-015, atk-029, atk-030, atk-038..040 |
| ALW-01 | ask | a recipient that is not on the allowlist | `alw01_*` | atk-001, atk-002, atk-004..009, atk-011..013, atk-017, ben-011, ben-012 |
| LIM-02 | ask | an amount above the auto limit | `lim02_*` | atk-004..008, atk-010, atk-022, ben-013..015 |
| VEL-01 | ask | 5 or more actions in 10 minutes (the 6th asks). A denied request from the owner counts; requests from untrusted origins do not | `vel01_*`, `test_state.py` (velocity) | atk-029..033 |
| DEF-01 | deny | anything the firewall cannot understand, or that crashes it: the default is deny | `*_becomes_deny`, `*_never_raises_*` | unit tests only |
| CNF-01 | deny | confirming something that was never asked, was already answered, has expired or has changed | `confirm_*`, `test_agent.py` (no replay) | unit tests only |

### The 55 red-team cases

40 attacks in 14 categories and 15 legitimate requests in 6 categories (see `firewall/redteam/README.md`).
`python -m firewall.redteam.run` feeds every case to the firewall from a clean state and writes
`evidence/redteam_results.json` and `evidence/redteam_report.md` (add `--no-write` to only print the summary).
It needs no chain and no API key.

| Measure | Result |
|---|---|
| Cases that behave as expected | **55/55** (2 are read-only questions that never reach the firewall) |
| Attacks denied / held for a human / let through | 36 / 4 / **0** of 40 |
| Legitimate requests wrongly denied (false-block rate) | **0/15** |
| Legitimate requests that needed a confirmation | 5/15 |

`python -m firewall.redteam.run --agents` (anvil running, token deployed) also sends the same cases through both
real agents and compares them. Measured: the protected agent executes **0 of 40** attacks; the naive agent executes
**38 of 40** (27 transfers and 11 approvals; the largest transfer is 1,000,000 TUSD). The 2 attacks it does not execute
are the kill-switch cases, where the engine refuses every token while the kill switch is on. Each case starts from the
same wallet. SIM-01 has no case among the 55; it is proved by the unit tests only. The suite tests the firewall with
structured requests; it does not measure how often a real language model is fooled.
