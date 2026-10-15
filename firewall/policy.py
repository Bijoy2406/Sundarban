"""The policy engine: the firewall's brain (Person 2 owns), issue #15.

evaluate(req, plan, sim) looks at ONE requested action and answers allow / ask / deny.
confirm(req, plan)        is called after a human clicked "Yes" on an "ask"; it re-checks the hard
                          rules and, if they still pass, issues the approval token.

Plain Python, no AI. Rules (deny > ask > allow, default deny):
  DENY  PRV-01 untrusted origin         KIL-01 kill switch on          NET-01 wrong chain id
        TOK-01 not our token contract   APR-01 unlimited approval      APR-02 approval to a spender not on the allowlist
        ADR-01 look-alike address       SIM-01 simulation failed / does not match the request
        LIM-01 over max per transaction LIM-03 over the rolling daily cap
        CNF-01 confirm() without a waiting question (nobody was asked)
        DEF-01 anything unexpected (default deny)
  ASK   ALW-01 new recipient            LIM-02 over the auto limit     VEL-01 too many actions too fast
  ALLOW only when no rule above fired.

Design choices that close loopholes:
  * Every number is read from the CALLDATA (what would really be signed, via wallet_engine/binding.py),
    and must match the request exactly (integer comparison, no rounding). A mismatch is a deny.
  * Only OUR token contract (TOKEN_ADDRESS in .env) may be used. Limits are in TUSD with 18 decimals,
    so a different token (other decimals, other value) would make every limit meaningless.
  * confirm() only works for a request that evaluate() really answered "ask", once, within a few minutes,
    and for the very same transaction. Nobody can skip the question by calling confirm() directly.
  * Approvals count as potential spending (an approved spender can pull that amount later).
  * evaluate/confirm run one at a time (a lock), so two parallel requests cannot both slip under the daily cap.
  * No audit entry, no money: if the "allow" cannot be written to the audit log, the answer becomes deny.
"""
import os
import threading
import time
from decimal import Context, Decimal, localcontext
from typing import Optional

from shared.types import ActionRequest, Decision, SimResult, TxPlan
from wallet_engine.binding import token_binding

from . import audit, provenance, state, tokens

TOKEN_DECIMALS = 18                       # TestUSD has 18 decimals (same as wallet_engine.erc20)
UNLIMITED_FROM = 2 ** 255                 # an approval this big is treated as "unlimited"
CONFIRM_WINDOW_SECONDS = 600              # a question stays open this long
MAX_PENDING = 1000                        # never remember more open questions than this
LOOKALIKE_CHARS = 6                       # leading + trailing hex digits shared with an allowlisted address

DENY, ASK = "deny", "ask"

_LOCK = threading.RLock()
_PENDING = {}                             # request_id -> (what was asked, deadline)


def reset() -> None:
    """Forget open questions (used by tests)."""
    with _LOCK:
        _PENDING.clear()


# ------------------------------------------------------------------ small helpers

def _norm(address) -> str:
    return str(address).strip().lower()


def _allowlist(rules: dict) -> set:
    return {_norm(a) for a in rules["allowlist"]}


def _allowed_tokens() -> set:
    """The only token contract(s) this wallet may touch: TOKEN_ADDRESS from .env."""
    value = os.getenv("TOKEN_ADDRESS", "").strip().lower()
    return {value} if value else set()


def _looks_like(address: str, allowed: set) -> Optional[str]:
    """Address-poisoning check: a DIFFERENT address that shares many leading + trailing digits with an allowlisted one."""
    a = _norm(address)
    if a in allowed or not a.startswith("0x") or len(a) != 42:
        return None
    for known in allowed:
        if len(known) != 42:
            continue
        lead = next((i for i in range(40) if a[2 + i] != known[2 + i]), 40)
        trail = next((i for i in range(40) if a[-1 - i] != known[-1 - i]), 40)
        if lead + trail >= LOOKALIKE_CHARS:
            return known
    return None


def _short(address: str) -> str:
    return f"{address[:6]}...{address[-4:]}"


def _to_raw(amount) -> Optional[int]:
    """'12.5' -> 12500000000000000000 exactly. None if it is not a clean, non-negative number."""
    try:
        value = Decimal(str(amount).strip())
        if not value.is_finite() or value < 0:
            return None
        raw = value.scaleb(TOKEN_DECIMALS)
        return int(raw) if raw == raw.to_integral_value() else None
    except Exception:
        return None


def _node_chain_id() -> Optional[int]:
    """Ask the connected node which chain it is. None if it cannot be reached."""
    try:
        from wallet_engine import chain       # imported here to avoid a circular import at load time
        return int(chain.get_web3().eth.chain_id)
    except Exception:
        return None


def _expected_chain_id(rules: dict) -> Optional[int]:
    return rules["chain_id"] if rules["chain_id"] is not None else _node_chain_id()


def _fingerprint(binding: dict) -> tuple:
    return (binding["action"], binding["token"], binding["to"], binding["amount"])


# ------------------------------------------------------------------ the checks

def _assess(req: ActionRequest, plan: Optional[TxPlan], sim: Optional[SimResult], confirming: bool):
    """Run every rule. Returns (findings, binding). findings = [(rule_id, 'deny'|'ask', reason), ...]."""
    rules = state.load_rules()
    allowed = _allowlist(rules)
    findings = []

    def add(rule_id, level, reason):
        findings.append((rule_id, level, reason))

    # PRV-01: where did the request come from?
    hit = provenance.check(req)
    if hit:
        add(hit[0], DENY, hit[1])

    # KIL-01: emergency stop
    if state.kill_switch_on():
        add("KIL-01", DENY, "The kill switch is ON, so the wallet is frozen and cannot send anything.")

    if plan is None:
        add("DEF-01", DENY, "There is no transaction plan to check, so the request is refused by default.")
        return findings, None

    # NET-01: right network?
    expected = _expected_chain_id(rules)
    if expected is None:
        add("NET-01", DENY, "The wallet could not confirm which network it is on, so it refuses to act.")
    elif plan.chain_id != expected:
        add("NET-01", DENY, f"This transaction is for network {plan.chain_id}, but the wallet is set up for network {expected}.")

    # What would REALLY be signed (read from the calldata)?
    try:
        binding = token_binding(plan)
    except ValueError as exc:
        add("SIM-01", DENY, f"The transaction data could not be understood ({exc}), so it is refused.")
        return findings, None

    raw = int(binding["amount"])
    real_action = binding["action"]
    unlimited = real_action == "approve" and raw >= UNLIMITED_FROM
    real_amount = Decimal(raw).scaleb(-TOKEN_DECIMALS)

    # TOK-01: only our own token contract
    ours = _allowed_tokens()
    if not ours:
        add("TOK-01", DENY, "No token contract is configured (TOKEN_ADDRESS), so the wallet refuses to act.")
    elif binding["token"] not in ours or _norm(req.token) not in ours:
        add("TOK-01", DENY, f"{_short(binding['token'])} is not the wallet's own token. Only TestUSD may be moved.")

    # SIM-01 (part 1): does the real transaction match what was asked, to the last digit?
    problems = []
    if plan.value != 0:
        problems.append("it also tries to send native coin (ETH)")
    if real_action != req.action:
        problems.append(f"it would {real_action}, not {req.action}")
    if binding["token"] != _norm(req.token):
        problems.append("it uses a different token contract")
    if binding["to"] != _norm(req.to):
        problems.append("it goes to a different address")
    if real_action in ("transfer", "approve") and not unlimited:
        if _to_raw(req.amount) != raw:
            problems.append(f"the amount is {real_amount}, not {req.amount}")
    if real_action == "approve" and unlimited != (req.unlimited is True):
        problems.append("the unlimited flag does not match the transaction")
    if problems:
        add("SIM-01", DENY, "The transaction does not match the request: " + "; ".join(problems) + ".")

    # SIM-01 (part 2): did the dry run work, and does it move no more than asked?
    if not confirming:
        if sim is None or not sim.ok:
            why = getattr(sim, "revert_reason", None) or "no simulation result"
            add("SIM-01", DENY, f"The dry run failed ({why}), so the transaction would not work as expected.")
        else:
            try:
                outflow = Decimal(str(sim.outflow))
                if real_action == "transfer" and outflow > Decimal(str(req.amount)):
                    add("SIM-01", DENY, f"The dry run shows {sim.outflow} leaving the wallet, more than the {req.amount} requested.")
                elif real_action != "transfer" and outflow != 0:
                    add("SIM-01", DENY, "The dry run shows tokens leaving the wallet during an approval, which should never happen.")
            except Exception:
                add("SIM-01", DENY, "The dry run reported an amount that could not be read.")

    # Action-specific rules
    if real_action == "transfer":
        target = binding["to"]
        known = _looks_like(target, allowed)
        if known:
            add("ADR-01", DENY, f"The address {_short(target)} looks almost identical to your saved address "
                                f"{_short(known)} but is a different address (a common scam trick).")
        _check_amount(add, rules, real_amount, unlimited=False)
        if target not in allowed and not known:
            add("ALW-01", ASK, f"{_short(target)} is a new recipient that is not on your allowlist.")

    elif real_action == "approve":
        spender = binding["to"]
        if unlimited:
            add("APR-01", DENY, "This would give another address UNLIMITED permission to spend your tokens.")
        known = _looks_like(spender, allowed)
        if known:
            add("ADR-01", DENY, f"The address {_short(spender)} looks almost identical to your saved address "
                                f"{_short(known)} but is a different address (a common scam trick).")
        elif spender not in allowed:
            add("APR-02", DENY, f"{_short(spender)} is not on your allowlist, so it may not get permission to spend your tokens.")
        _check_amount(add, rules, real_amount, unlimited=unlimited)

    # real_action == "revoke": taking permission away is always safe, no extra rules.

    # VEL-01: too many actions too fast (a human who just confirmed is not asked again)
    if not confirming:
        used = state.actions_in_window()
        if used >= rules["velocity_max_actions"]:
            minutes = rules["velocity_window_seconds"] // 60
            add("VEL-01", ASK, f"{used} actions were already made in the last {minutes} minutes, "
                               f"which is more than the {rules['velocity_max_actions']} allowed, so a person must check this one.")

    return findings, binding


def _check_amount(add, rules, amount: Decimal, unlimited: bool) -> None:
    """LIM-01 / LIM-03 (deny) and LIM-02 (ask). Unlimited approvals are already handled by APR-01.
    Approvals count too: whatever may be pulled out later counts as potential spending."""
    if unlimited:
        return
    if amount > rules["max_tx"]:
        add("LIM-01", DENY, f"{amount} TUSD is above the maximum of {rules['max_tx']} TUSD per transaction.")
    elif amount > rules["auto_limit"]:
        add("LIM-02", ASK, f"{amount} TUSD is above the {rules['auto_limit']} TUSD that can be sent without asking you.")
    already = state.spent_last_24h()
    if already + amount > rules["daily_cap"]:
        add("LIM-03", DENY, f"{already} TUSD was already sent or approved in the last 24 hours; adding {amount} would pass "
                            f"the daily cap of {rules['daily_cap']} TUSD.")


# ------------------------------------------------------------------ public API

def _decide(findings) -> str:
    levels = {level for _, level, _ in findings}
    return DENY if DENY in levels else ASK if ASK in levels else "allow"


def _deny(request_id, rule_id: str, reason: str) -> Decision:
    return Decision(request_id=request_id, decision=DENY, rule_ids=[rule_id], reasons=[reason], approval_token=None)


def _log(req, decision: Decision, strict: bool = False) -> None:
    """Write the decision to the audit log. Best effort, unless strict (then a failure is raised)."""
    event = {"event": "DECISION", "request_id": getattr(req, "request_id", None), "action": getattr(req, "action", None),
             "origin": getattr(req, "origin", None), "decision": decision.decision, "rule_ids": decision.rule_ids}
    try:
        audit.log(event)
    except Exception:
        if strict:
            raise


def _safe_assess(req, plan, sim, confirming):
    try:
        with localcontext(Context(prec=120)):          # exact arithmetic for 256-bit numbers
            return _assess(req, plan, sim, confirming)
    except Exception as exc:     # default deny: any bug or odd input ends in "deny", never "allow"
        return [("DEF-01", DENY, f"The firewall hit an unexpected problem ({type(exc).__name__}), so it refuses by default.")], None


def _finish(req: ActionRequest, findings, binding, allow_reason: str) -> Decision:
    outcome = _decide(findings)
    if outcome != "allow":
        decision = Decision(request_id=req.request_id, decision=outcome, rule_ids=[r for r, _, _ in findings],
                            reasons=[text for _, _, text in findings], approval_token=None)
        _log(req, decision)
        return decision

    # allow: create the token, write the audit entry (must succeed), and only then count the spend
    try:
        token = tokens.issue_token(req.request_id, binding["action"], binding["token"], binding["to"], binding["amount"])
    except Exception:
        decision = _deny(req.request_id, "DEF-01", "The approval token could not be created (is APPROVAL_SECRET set?), so the request is refused.")
        _log(req, decision)
        return decision
    decision = Decision(request_id=req.request_id, decision="allow", rule_ids=["ALLOW"], reasons=[allow_reason], approval_token=token)
    try:
        _log(req, decision, strict=True)
    except Exception:
        decision = _deny(req.request_id, "DEF-01", "The decision could not be written to the audit log, so nothing is allowed (no audit, no money).")
        _log(req, decision)
        return decision
    if binding["action"] in ("transfer", "approve"):
        with localcontext(Context(prec=120)):
            state.record_spend(Decimal(binding["amount"]).scaleb(-TOKEN_DECIMALS))
    return decision


def _prune_pending(now: float) -> None:
    for rid in [r for r, (_, deadline) in _PENDING.items() if deadline < now]:
        del _PENDING[rid]
    while len(_PENDING) > MAX_PENDING:
        del _PENDING[next(iter(_PENDING))]


def evaluate(req: ActionRequest, plan: Optional[TxPlan] = None, sim: Optional[SimResult] = None) -> Decision:
    if not isinstance(req, ActionRequest):
        return _deny("unknown", "DEF-01", "The request was not in a form the firewall understands, so it is refused by default.")
    with _LOCK:
        findings, binding = _safe_assess(req, plan, sim, confirming=False)
        state.record_action()          # every request counts toward VEL-01, even denied ones
        now = time.time()
        _prune_pending(now)
        _PENDING.pop(req.request_id, None)
        decision = _finish(req, findings, binding, "Every safety check passed.")
        if decision.decision == ASK and binding is not None:
            _PENDING[req.request_id] = (_fingerprint(binding), now + CONFIRM_WINDOW_SECONDS)
        return decision


def confirm(req: ActionRequest, plan: Optional[TxPlan] = None) -> Decision:
    if not isinstance(req, ActionRequest):
        return _deny("unknown", "DEF-01", "The request was not in a form the firewall understands, so it is refused by default.")
    with _LOCK:
        findings, binding = _safe_assess(req, plan, None, confirming=True)
        findings = [f for f in findings if f[1] == DENY]       # the person already accepted the "ask" reasons

        # CNF-01: there must be an open question for exactly this transaction
        now = time.time()
        _prune_pending(now)
        waiting = _PENDING.get(req.request_id)
        if waiting is None:
            findings.append(("CNF-01", DENY, "Nobody was asked about this request (or the question expired), so it cannot be confirmed."))
        elif binding is None or waiting[0] != _fingerprint(binding):
            findings.append(("CNF-01", DENY, "The transaction being confirmed is not the one the person was asked about."))

        decision = _finish(req, findings, binding, "You confirmed this action and the hard safety checks still pass.")
        if decision.decision == "allow":
            _PENDING.pop(req.request_id, None)                  # a question can be answered only once
        return decision