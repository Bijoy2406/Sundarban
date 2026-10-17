# Sundarban — Demo Video Script (target: 4:30)

**Maximum:** 5 minutes. This is a recording script; the video has not been recorded by committing this file. Use a clean browser profile and a local Anvil chain with test tokens.

## 0:00–0:20 — Title and setup
**On screen:** Wallet UI title; status indicator showing local chain 31337 and TestUSD deployed. Avoid showing terminal windows containing environment variables.

**Narration:** “Sundarban separates language understanding from transaction authorization. This demo uses a local development chain and test tokens only.”

## 0:20–1:05 — Legitimate transfer
**On screen:** Enter the approved 10 TUSD transfer. Show the preview and simulation. Click Execute only if the server-side decision is allow. Wait for the mined receipt, then show the returned hash and updated balance.

**Narration:** “The agent extracts a structured intent. The server builds and simulates the exact transaction, and the deterministic firewall evaluates it. Execution happens only after the server returns allow.”

**Evidence to capture:** actual local chain ID, actual transaction hash and before/after test-token balances.

## 1:05–1:45 — Human confirmation
**On screen:** Use a configured new recipient so the firewall returns ask. Show that no transaction hash exists before confirmation. Click the separate Confirm control; show the final decision and receipt.

**Narration:** “A request requiring confirmation is not sent immediately. A separate human action is required, and the firewall checks the pending request again before execution.”

**Evidence to capture:** ask decision, no pre-confirm transaction, final receipt. Do not claim this segment succeeded if the run did not.

## 1:45–2:35 — Public-feed attack
**On screen:** Choose a synthetic public-feed instruction in the attack replay. Show the source label and the protected agent's denial reason, ideally PRV-01. Show that no transaction hash is returned for the protected side.

**Narration:** “Instructions from public content are marked untrusted by application code. The content cannot assign itself a trusted origin or override the policy.”

## 2:35–3:35 — Side-by-side replay
**On screen:** Run the same synthetic attack against both sides. Left panel: naive-agent transaction and drainer result on local Anvil, if the fixture actually succeeds. Right panel: protected-agent denial and rule reason.

**Narration:** “The naive agent intentionally omits firewall policy evaluation. The protected agent applies the same deterministic policy. This contrast is confined to a local test chain.”

**Safety:** If the naive side doesn't successfully create the required allowance and drain, show the actual failure rather than fabricating a balance drop. Never run the drainer against Sepolia or mainnet.

## 3:35–4:05 — Kill switch and audit
**On screen:** Enable kill switch; show a request denied with KIL-01. Open the audit viewer and show integrity status. Do not show secrets or full environment configuration.

**Narration:** “The emergency switch blocks actions, and the audit log provides a hash-linked record that can be checked for tampering.”

## 4:05–4:30 — Close
**On screen:** Final wallet screen and repository URL.

**Narration:** “Sundarban keeps authorization in deterministic code, requires human confirmation when needed, and makes decisions inspectable. All transactions in this demo use test assets.”

## Recording checklist
- [ ] Recorded duration is 4:30 or less, never over 5 minutes.
- [ ] No private key, API key, approval secret, .env file or terminal secret appears on screen.
- [ ] Chain ID and network are visible enough to prove this is local Anvil.
- [ ] All shown hashes and balances come from the actual run.
- [ ] No simulated, skipped or failed test is described as a pass.
- [ ] Captions/narration and UI labels are in English.
- [ ] Video playback and audio have been checked after export.
