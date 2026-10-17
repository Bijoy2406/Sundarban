# Submission Package — Checklist and Email Draft

**Deadline from project context:** 20 October 2026, 23:59 Beijing time (UTC+8). Internal target: send by noon Beijing time on 20 October.

**Recipient from project context:** wangyr@pbcsf.tsinghua.edu.cn  
**Sepolia evidence:** the organizer confirmed that Sepolia testnet transaction hashes are accepted (see evidence/tx_hashes.csv).

## Required package

- [ ] **Source code:** public GitHub repository URL, README, setup/deployment instructions and test-case index.
- [ ] **Technical document:** reviewed by all three contributors. This repository currently has an assembled draft at technical_overview.md; authoritative Person 1/2 sections should be reviewed/added by those owners.
- [ ] **Security self-assessment:** permission tiers, OWASP LLM01 and Agentic ASI01/02/03/06/09 mapping, residual risks and honest “not solved” list. Person 2 owns this artifact; it was not present in the inspected docs paths when this checklist was written.
- [ ] **Deck:** exported presentation, 10 minutes maximum. Use presentation_outline.md, then export and rehearse the actual deck.
- [ ] **Demo video:** exported video, 5 minutes maximum. Use demo_video_script.md. No keys or secrets may appear on screen.
- [ ] **Execution evidence:** real recorded transaction hashes, network names, relevant outcomes and audit evidence. Keep a clear distinction between local Anvil evidence and public testnet evidence.
- [ ] **Test results:** record the exact command, date, pass/skip/fail counts and platform. Skipped E2E tests are not passes.
- [x] **Organizer response:** Sepolia testnet hashes are accepted; keep the organizer's reply with the submission records.
- [ ] **Final review:** check that all attachments open and the repository URL is accessible.
- [ ] **Email sent:** mark only after the email has actually been sent and retain the sent-message record.

## Final email draft

**To:** wangyr@pbcsf.tsinghua.edu.cn  
**Subject:** FinTechathon 2026 — Sentinel Wallet Submission (International Track, Topic F)

Dear Organizing Team,

Please find our Sentinel Wallet submission for FinTechathon 2026, International Track, Topic F (Agent Wallet).

Sentinel Wallet demonstrates an AI-assisted ERC-20 wallet in which a deterministic firewall—not the LLM—decides whether an action is allowed, requires explicit human confirmation, or must be denied.

**Submission materials**
1. Source code and setup instructions: https://github.com/Bijoy2406/Sentinel-Wallet
2. Technical document: [attach reviewed PDF]
3. Presentation deck (10 minutes or less): [attach exported deck]
4. Demo video (5 minutes or less): [attach exported video or provide approved link]
5. Security self-assessment: [attach Person 2's reviewed report]
6. Execution evidence and test results: [attach verified hashes, network labels, audit evidence and test summary]

All demo transactions use test assets on local Anvil and/or the explicitly identified test network. We have not used mainnet or real funds.

Thank you for your time and consideration.

Best regards,  
Sentinel Wallet Team  
FinTechathon 2026 — International Track, Topic F

---

**Do not send this draft until every bracketed item is resolved.** Make sure the claims match the evidence attached.

## Final handoff checklist (day of submission)

- [ ] Code freeze and PR review complete.
- [ ] Clean-checkout setup rehearsed by someone other than the primary developer.
- [ ] Final deck timed at 10 minutes or less.
- [ ] Final video timed at 5 minutes or less; secrets scan complete.
- [ ] Technical and security reports approved by their owners.
- [ ] Evidence hashes independently checked against the stated network.
- [ ] Email and attachments sent before the deadline.
- [ ] Sent email and exact submission artifacts archived.
