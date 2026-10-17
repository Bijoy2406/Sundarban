## 12. Test cases

Run all of them:

```bash
python -m pytest -q
```

| Situation | Result at the time of writing |
|---|---|
| anvil running, token deployed | **987 passed, 1 skipped** (a retired check in `test_evidence_run.py`) |
| no anvil | 938 passed, 50 skipped: the 49 tests that need the local chain show as `s` |

The counts grow as tests are added; `python -m pytest --collect-only -q | tail -1` gives the current total.
Every live test uses the **local** chain only and is rolled back afterwards (`evm_snapshot` / `evm_revert`),
so the wallet is unchanged when the tests finish.

### Which test file proves what

**Firewall** (`firewall/`, Person 2)

| Test file | Tests | Needs anvil | What it proves |
|---|---|---|---|
| `tests/test_policy_preview.py` | 267 | no | The policy engine (issue #15), and the main policy suite despite its name. Every rule fires when it should and only then; deny beats ask beats allow; reasons are plain English; an approval token is tied to the exact transaction; a confirmation works only after an ask, only once, and never overrides a deny; any crash or odd input ends in deny. |
| `tests/test_policy.py` | 71 | no | The first version of the same suite. Every one of its cases is also in `test_policy_preview.py`. |
| `tests/test_provenance.py` | 90 | no | Only `user_chat` is trusted (PRV-01). Every other origin, look-alike name, odd type or broken rules file is denied, and reasons never repeat outside text. |
| `tests/test_state.py` | 294 | no | The firewall's memory (issue #13): the strict `rules.yaml` loader, exact 24-hour spending in a tamper-evident ledger, the velocity count, and the kill switch (survives a restart, fails safe), also under parallel use. |
| `tests/test_tokens.py` | 22 | no | HMAC approval tokens (issue #16). A valid token passes; a wrong amount, recipient, action, token contract or request id, an expired, tampered or foreign-secret token all fail. |
| `tests/test_tokens_hardening.py` | 5 | no | A token works once; a failed check does not use it up; the kill switch cancels tokens that were already issued. |
| `tests/test_audit.py` | 29 | no | The hash-chained audit log (issue #17). Editing, deleting, inserting, re-ordering or duplicating a line is detected; secrets are redacted; threads and processes can share one log. |
| `tests/test_audit_locking.py` | 8 | no | The audit log stays intact when several processes write at once, including on Windows and on drives without `flock`. |

**Red-team** (`firewall/redteam/`, Person 2)

| Test file | Tests | Needs anvil | What it proves |
|---|---|---|---|
| `tests/test_redteam_data.py` | 18 | no | The 55 cases are well formed, and a small reference model of the rule table agrees with every expected answer, so the data cannot quietly contradict the rules. |
| `tests/test_redteam_runner.py` | 31 | 1 test | The runner reports 55/55 on the real firewall; it notices a firewall that allows everything, one that denies everything, a removed rule and a changed limit; cases stay isolated; it refuses any chain but the local one. The live test sends the same attacks to both agents on anvil. |

**Wallet engine** (`wallet_engine/`, Person 1)

| Test file | Tests | Needs anvil | What it proves |
|---|---|---|---|
| `tests/test_erc20.py` | 14 | 4 | Amount conversion both ways; building transfer, approve, unlimited approve and revoke transactions; decoding calldata; reading balances and allowances. |
| `tests/test_simulate_execute.py` | 27 | 10 | The dry run (`simulate`) and the sender (`execute`). What a token must bind to; `execute` refuses anything without a matching approval token; a plan cannot be swapped after approval; the live tests send real test transactions. |
| `tests/test_testusd_local.py` | 6 | 6 | TestUSD behaves like a standard ERC-20: transfers, limited and unlimited approvals (unlimited is never used up), revoke. |
| `tests/test_drainer.py` | 17 | 12 | The attacker script refuses any chain but local 31337 and never shows its key. Against a naive wallet it drains what a granted allowance allows, and revoking stops it. |
| `tests/test_evidence_run.py` | 9 | 3 (+1 retired) | The Sepolia evidence script: refuses to send without `--yes`, covers the scenarios the issue asks for, writes an audit trail that verifies, and fails the run if a decision is wrong. |

**Agents and API** (`agent/`, `api/`, Person 3)

| Test file | Tests | Needs anvil | What it proves |
|---|---|---|---|
| `tests/test_agent.py` | 8 | no | The protected agent's pipeline with stand-ins: an allowed request is sent, an ask waits for a confirmation that cannot be replayed, a denied request never executes, a parse failure gets a polite answer. |
| `tests/test_intents.py` | 12 | no | Messages become strict intent JSON (fake model): invalid output is retried once, then refused; untrusted text is fenced in and cannot close its wrapper. |
| `tests/test_feed.py` | 7 | no | The synthetic public posts and NFT metadata (3 harmless, 6 attacks): their origin is set by code and cannot be influenced by their text. |
| `tests/test_resolve.py` | 25 | no | Token symbol to contract address, and 0x-address checks (a mistyped checksum is caught), shared by both agents. |
| `tests/test_naive_agent.py` | 3 | no | The deliberately unsafe agent refuses any chain but local 31337 and, with no firewall, executes what the model extracted. |
| `tests/test_api.py` | 9 | no | The HTTP backend with stand-ins: execute sends only on allow; an ask needs a separate confirm; a decision sent by the browser is ignored; a replayed confirm is rejected; the LLM key is never returned. |
| `tests/test_live_agents_api.py` | 13 | 13 | Both agents and the API against the real firewall and a real local chain. The same text is allowed from the chat and denied from a public post; an unlimited approval is denied; Preview changes nothing; a naive wallet is drained after it signs an unlimited approval. |
| `tests/test_contract.py` | 3 | no | The shared contract: the data types keep their fields and every facade function keeps its signature. It fails if someone changes them. |

### Rule by rule: where each firewall rule is proved

The red-team cases are in `firewall/redteam/attacks.jsonl` (`atk-`) and `benign.jsonl` (`ben-`).
"Unit tests" are in `tests/test_policy_preview.py` unless another file is named.

| Rule | Decision | What it stops | Unit tests | Red-team cases |
|---|---|---|---|---|
| PRV-01 | deny | any action triggered by text from outside the owner's own chat (public posts, NFT metadata, tool output) | `test_provenance.py` | atk-005..014, atk-017 |
| KIL-01 | deny | everything while the emergency stop is on | `kil01_*`, `test_state.py` (kill switch), `test_tokens_hardening.py` | atk-034..035 |
| NET-01 | deny | a transaction for the wrong network, or when the network cannot be confirmed | `net01_*` | atk-027..028 |
| TOK-01 | deny | moving any token other than TestUSD | `tok01_*` | unit tests only |
| DST-01 | deny | sending to a burn address or to the token contract itself | `dst01_*` | unit tests only |
| APR-01 | deny | an unlimited approval | `apr01_*`, `test_live_agents_api.py` | atk-003, atk-016, atk-018..020 |
| APR-02 | deny | an approval for a spender that is not on the allowlist | `apr02_*` | atk-021..023 |
| ADR-01 | deny | an address that looks like an allowlisted one (same first and last 6 digits) but is different | `adr01_*` | atk-024..026 |
| SIM-01 | deny | a failed dry run, or a real transaction that differs from the request (recipient, amount, token, native coin), or more tokens leaving than asked | `sim01_*` | unit tests only |
| LIM-01 | deny | a transfer or approval above the per-transaction maximum | `lim01_*` | atk-001..002, atk-015, atk-036..038 |
| LIM-03 | deny | passing the daily cap in 24 hours (approvals count too) | `lim03_*`, `test_state.py` (24-hour window, ledger) | atk-029..030, atk-039..040 |
| ALW-01 | ask | a recipient that is not on the allowlist | `alw01_*` | atk-004, ben-011..012 |
| LIM-02 | ask | an amount above the auto limit | `lim02_*` | ben-013..015 |
| VEL-01 | ask | more than 5 actions in 10 minutes. A denied request from the owner counts; requests from untrusted origins do not | `vel01_*`, `test_state.py` (velocity) | atk-031..033 |
| DEF-01 | deny | anything the firewall cannot understand, or that crashes it: the default is deny | `*_becomes_deny`, `*_never_raises_*` | unit tests only |
| CNF-01 | deny | confirming something that was never asked, was already answered, has expired or has changed | `confirm_*`, `test_agent.py` (no replay) | unit tests only |

### The 55 red-team cases

40 attacks in 14 categories and 15 legitimate requests in 6 categories (see `firewall/redteam/README.md`).
`python -m firewall.redteam.run` feeds every case to the firewall from a clean state and writes
`evidence/redteam_results.json` and `evidence/redteam_report.md`. It needs no chain and no API key.

| Measure | Result |
|---|---|
| Cases that behave as expected | **55/55** (2 are read-only questions that never reach the firewall) |
| Attacks denied / held for a human / let through | 36 / 4 / **0** of 40 |
| Legitimate requests wrongly denied (false-block rate) | **0/15** |
| Legitimate requests that needed a confirmation | 5/15 |

`python -m firewall.redteam.run --agents` (anvil running, token deployed) also sends the same cases through both
real agents and compares them: the protected agent executes 0 of 40 attacks; the naive agent executes 38 of 40
(the 2 kill-switch attacks stop at the engine, which refuses every token while the kill switch is on).
Each case starts from the same wallet.
SIM-01 has no case among the 55; it is proved by the unit tests only.