# Sundarban — Technical Overview

**Competition:** FinTechathon 2026, International Track, Topic F (Agent Wallet)  
**Repository:** https://github.com/Bijoy2406/Sundarban

> **Safety boundary:** test tokens only. Use local Anvil (chain ID 31337) and, where approved, Sepolia. Never use mainnet or a wallet containing real funds.

## 1. Problem and design goal

An LLM agent can encounter malicious instructions in chat, public posts, NFT metadata, or tool output. Such text may attempt to override policy, impersonate an administrator, or induce an unsafe token approval. Sundarban treats the LLM as an intent extractor—not as an authorization system.

The central rule is: **permission never comes from text**. Trusted application code sets request provenance. The firewall evaluates the transaction request and simulation using deterministic rules. A high-risk action can be denied; an action that requires a human decision remains pending until a separate confirmation step succeeds.

## 2. Architecture

~~~text
Chat / trusted UI action
        |
        v
Intent parser (strict JSON; no origin or permission field)
        |
        v
Application assigns origin -> ActionRequest
        |
        v
wallet_engine.plan -> exact TxPlan
        |
        v
wallet_engine.simulate -> SimResult
        |
        v
firewall.evaluate -> allow | ask | deny
        |                 |       |
        | allow           | ask   | deny
        v                 v       v
wallet_engine.execute   human UI  return reasons
                        confirm
                           |
                           v
                    firewall.confirm
                           |
                     allow or deny
                           |
                           v
                   execute only on allow
                           |
                           v
                 transaction hash + audit log
~~~

The backend is authoritative. A browser-supplied decision is not accepted as permission: the server rebuilds the plan, simulates it and calls the firewall itself. For an ask decision, the server remembers the pending request and exact transaction plan; the user must take a separate confirmation action. Confirmation is checked by the firewall before execution.

## 3. Wallet engine (Person 1 contribution)

The wallet engine is implemented with web3.py and Foundry tooling.

- **Chain configuration:** wallet_engine/chain.py reads ACTIVE_NETWORK, RPC_URL_LOCAL or RPC_URL_SEPOLIA, and TOKEN_ADDRESS from the environment. It reports connectivity, chain ID and whether bytecode exists at the configured token address.
- **ERC-20 operations:** the engine reads balances and allowances and builds transfer, approve and revoke transaction plans.
- **Planning:** wallet_engine.plan(req) builds a TxPlan containing the transaction target, calldata, gas estimate, chain ID and human-readable summary.
- **Simulation:** wallet_engine.simulate(plan) performs a dry-run and returns a structured result; a failed simulation is a denial condition.
- **Execution:** wallet_engine.execute(plan, decision) requires an allow decision with a valid approval token. It checks the token against the exact transaction binding, checks chain and signer consistency, simulates again immediately before signing, submits the signed transaction and waits for a receipt.
- **Test asset:** TestUSD is a test ERC-20 contract. Its deployment address is environment-specific; after restarting Anvil, redeploy it and update TOKEN_ADDRESS.

The naive agent and drainer are intentionally unsafe demonstration components. They must refuse to operate unless the active network is local and the node reports chain ID 31337.

## 4. Deterministic firewall (Person 2 contribution)

The firewall is regular Python policy code, not an LLM. It evaluates the request, transaction plan and simulation, and returns a structured Decision containing the decision, rule IDs and reasons.

| Rule | Purpose |
|---|---|
| PRV-01 | Deny actions caused by an untrusted origin |
| KIL-01 | Deny while the emergency kill switch is enabled |
| NET-01 | Deny a transaction on the wrong chain |
| APR-01 | Deny unlimited approvals |
| APR-02 | Deny approvals to a non-allowlisted spender |
| ADR-01 | Deny look-alike recipient/spender addresses |
| SIM-01 | Deny failed simulations or excess outflow |
| LIM-01 / LIM-03 | Enforce per-transaction and rolling daily limits |
| ALW-01 | Ask for human confirmation for a new recipient |
| LIM-02 / VEL-01 | Ask when configured auto/velocity thresholds are crossed |

The project configuration documents an auto limit of 50 TUSD, a maximum transaction of 500 TUSD, a rolling daily cap of 1,000 TUSD and a velocity threshold of more than five actions in ten minutes. The active policy is defined by the checked-in firewall implementation and firewall/rules.yaml; verify the active demo configuration before relying on any threshold.

### Confirmation tokens

The firewall's HMAC-SHA256 token binds an approval to the request ID, action, token, recipient/spender, amount and expiry. Verification rejects mismatches, expired or previously used tokens, and tokens while the kill switch is on. The execution layer verifies the binding against the transaction plan before signing.

### Audit log

The audit logger writes JSON Lines entries linked by hashes. Verification can detect changes, deletions in the middle, insertion and reordering that break the chain. Secrets such as private keys and approval tokens must not be logged. A valid shortened log cannot prove that a final suffix was not deleted unless its expected head hash is stored independently.

## 5. Agent and public input handling (Person 3 contribution)

- agent/intents.py asks the LLM for strict structured intent data and validates the schema; malformed output is retried once and then refused politely.
- The intent schema excludes origin and permission decisions.
- Text from untrusted sources is marked with <untrusted> delimiters before it is passed for interpretation.
- agent/agent.py orchestrates parse → plan → simulate → evaluate → optional human confirmation → execute.
- agent/naive_agent.py is intentionally unprotected and exists only to demonstrate the risk on the local test chain.
- agent/feed.py provides a synthetic public/NFT feed with benign and attack examples. The backend maps the feed source to provenance; it does not accept provenance asserted by the content itself.

## 6. API and user interface

The FastAPI backend exposes health/status, preview/planning, execution and confirmation functionality, plus chat, kill-switch, audit and attack-replay endpoints. The React/Vite UI provides a chat input, transaction preview, color-coded decision state, confirmation action, kill-switch control, audit viewer and side-by-side attack replay.

Safety-sensitive decisions remain server-side. The UI displays decisions and reasons; it does not authorize a transaction by sending a client-side decision value.

## 7. Reproduce the local setup

Requirements: Python 3.11+, Node.js 20.19+ or 22.12+, Foundry (anvil, forge, cast) and Git.

From the repository root:

~~~bash
python -m venv .venv
# Activate .venv using the command for your shell.
python -m pip install -r requirements.txt
cd ui && npm install && cd ..
cd wallet_engine && forge build && cd ..
cp .env.example .env
~~~

Set private values in .env; never commit it. For a local demo, configure ACTIVE_NETWORK=local, RPC_URL_LOCAL=http://127.0.0.1:8545, the Anvil test-account keys, a strong random APPROVAL_SECRET, and the deployed TOKEN_ADDRESS. Set the LLM provider values only if the live LLM connection is needed.

Use four terminals from the repository root:

1. Start the local chain: anvil.
2. Deploy TestUSD: python wallet_engine/scripts/deploy.py.
3. Start the backend: uvicorn api.main:app --reload --port 8000.
4. Start the UI: cd ui && npm run dev.

Open http://localhost:5173. Check backend status at http://127.0.0.1:8000/api/health and API documentation at http://127.0.0.1:8000/docs. The health response should indicate connection to chain 31337 and a deployed token.

## 8. Tests and evidence

Run from the repository root:

~~~bash
python -m pytest tests/test_contract.py -v
python -m pytest tests/test_intents.py -v
python -m pytest tests/test_feed.py -v
python -m pytest tests/test_agent.py -v
python -m pytest tests/test_api.py -v
python -m pytest tests/test_attack_replay.py -v
python -m pytest tests/test_e2e.py -v
python -m pytest -q
python scripts/verify_audit.py
~~~

The five E2E scenarios require a reachable local Anvil node on chain ID 31337 and a deployed TestUSD contract. If they are skipped, they have **not** demonstrated the live pipeline. Never remove the chain guard merely to force a pass.

For on-chain evidence, follow the README instructions for wallet_engine/scripts/evidence_run.py and record transaction hashes, network, outcomes and audit evidence. The organizer confirmed that Sepolia testnet transaction hashes are accepted as execution evidence. The recorded run is in evidence/tx_hashes.csv, evidence/audit_sepolia.jsonl and evidence/audit_head_sepolia.json.

## 9. Security boundaries and known limitations

- No mainnet and no real funds. The naive agent/drainer are local-chain-only.
- Keep all private keys and APPROVAL_SECRET out of source control, screenshots, recordings, logs and submitted artifacts.
- The LLM is not an authorization authority. The application assigns origin; the firewall evaluates policy.
- A separate confirmation action is required for ask; chat text must never simulate a human confirmation.
- A local test suite that uses mocks verifies behavior at those seams, not the live blockchain.
- E2E scenarios are only verified when they execute against the configured local chain and token contract.
- The Windows audit-log corruption (no fcntl module) was fixed in issue #17 with a cross-process lock (msvcrt on Windows, a portable lock file elsewhere). tests/test_audit_locking.py forces both code paths with several writer processes; re-run the suite on a real Windows machine before the final submission.
- The team must attach its final security self-assessment and actual test/evidence results. Do not claim an unrecorded test, transaction, review or submission happened.

## 10. Submission evidence checklist

- [ ] Final technical document reviewed by Persons 1, 2 and 3.
- [ ] Security self-assessment from Person 2, including red-team metrics and residual risks.
- [ ] Deck exported and timed to no more than 10 minutes.
- [ ] Demo video recorded and checked to no more than 5 minutes; no keys or secrets visible.
- [ ] Actual test output and on-chain evidence attached.
- [ ] Organizer's answer about acceptable chain/hash evidence confirmed.
- [ ] Final email sent to the organizer with the requested package.

This overview assembles information from the repository README, project context and implementation. Separate Person 1/2 authored technical documents and a final security report were not present in the inspected docs paths when this file was prepared; owners should review and contribute their authoritative sections before submission.
