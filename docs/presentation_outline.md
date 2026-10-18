# Sundarban — Presentation Outline (target: 8–9 minutes)

**Format:** 8 slides, English, 16:9. Keep the final exported deck at or below 10 minutes. This is a slide-content outline, not an exported presentation file. Replace bracketed evidence placeholders only after verification.

## Slide 1 — Title and one-sentence claim (0:00–0:35)
**Sundarban: An AI wallet agent that cannot authorize itself**
- FinTechathon 2026 · International Track · Topic F (Agent Wallet)
- Team and repository URL
- Claim: LLM extracts intent; deterministic firewall owns permission.

**Speaker note:** The goal is not to make the model perfectly resistant to every prompt. The goal is to keep authorization outside the model.

## Slide 2 — The failure mode (0:35–1:25)
**Prompt injection can become a transaction**
- Public post or NFT metadata contains malicious instructions.
- The agent reads the text as if it were trusted.
- A dangerous approval can give an attacker token-spending rights.
- No private key theft is required for a policy failure to cause loss.

**Speaker note:** Describe the threat pattern; don't claim this demo proves details of a real-world incident beyond what the team's source material supports.

## Slide 3 — Security principle and architecture (1:25–2:25)
**Text is input, never permission**
- Strict intent parser → trusted origin assignment → transaction plan → simulation.
- Deterministic firewall returns allow / ask / deny.
- Human confirmation is separate from chat.
- Execution requires a transaction-bound HMAC approval token.
- Hash-chained audit log records important outcomes.

## Slide 4 — Policy and defense in depth (2:25–3:20)
**Several independent checks, not one prompt**
- Untrusted provenance: PRV-01 deny.
- Unlimited approval: APR-01 deny.
- Kill switch: KIL-01 deny.
- Failed simulation, network mismatch and limits are checked by code.
- HMAC token binds the authorization to the exact transaction.

**Speaker note:** Mention only rules confirmed in the active policy configuration. Show real rule reasons from the demo, not fabricated examples.

## Slide 5 — Live wallet flow (3:20–4:15)
**A legitimate transfer remains usable**
- Show a 10 TUSD allowlisted transfer preview.
- Show plan/simulation and the decision card.
- Show transaction hash and resulting balance only after the transaction is actually mined.
- Evidence placeholder: [network, tx hash, block number].

**Speaker note:** Use local Anvil for the demonstration; if presenting Sepolia evidence, label it explicitly as testnet.

## Slide 6 — The side-by-side attack replay (4:15–5:50)
**Same synthetic attack, different outcome**
- Left: naive agent attempts the unsafe approval; local drainer demonstrates the consequence if allowance succeeds.
- Right: protected agent rejects the same untrusted-origin instruction and displays the firewall reason.
- Show before/after test-token balances and transaction hashes from the actual run.

**Speaker note:** The drainer must only run on Anvil chain ID 31337. Never use real assets. Do not claim a loss occurred unless the recorded local-chain result shows it.

## Slide 7 — Evidence, evaluation and limits (5:50–7:10)
**What we measured—and what remains**
- Test suite: [insert current executed pass/skip/fail counts].
- Red-team results: [insert Person 2's verified block rate and false-block rate].
- Chain evidence: [insert verified hashes and network].
- Known limitations: live E2E cases are not verified when skipped; the demo runs on test networks only (local Anvil and Sepolia).

**Speaker note:** Never describe skipped tests as passed. Don't invent red-team metrics or hashes.

## Slide 8 — Takeaway and Q&A (7:10–8:00)
**The model proposes; code disposes**
- Keep policy outside the LLM.
- Bind approvals to the exact transaction.
- Require explicit confirmation for ask decisions.
- Log decisions and preserve evidence.
- GitHub repository and contact/team details.

### Rehearsal checklist
- [ ] Complete the deck in 8–9 minutes, leaving margin below 10.
- [ ] Test every live UI action before presenting.
- [ ] Use only local Anvil test accounts/test tokens for the attack.
- [ ] Blur or hide terminal environment output and all secrets.
- [ ] Replace all placeholders with verified evidence or remove the claim.
- [ ] Confirm organizer's rules for qualifying on-chain hashes.
