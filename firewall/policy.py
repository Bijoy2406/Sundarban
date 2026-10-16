"""The policy engine: the firewall's brain (Person 2 owns), issue #15.  HARDENED version.

evaluate(req, plan, sim) looks at ONE requested action and answers allow / ask / deny.
confirm(req, plan)        is called after a human clicked "Yes" on an "ask"; it re-checks the hard
                          rules and, if they still pass, issues the approval token.
Neither function ever raises, and neither can answer "allow" because of an error.

Plain Python, no AI. Rules (deny > ask > allow, default deny):
  DENY  PRV-01 untrusted origin          KIL-01 kill switch on          NET-01 wrong chain id
        TOK-01 not our token contract    APR-01 unlimited approval      APR-02 approval to a spender not on the allowlist
        ADR-01 look-alike address        DST-01 burn address / the token contract itself
        SIM-01 simulation failed or the transaction does not match the request
        LIM-01 over max per transaction  LIM-03 over the rolling daily cap
        CNF-01 confirm() without a waiting question (nobody was asked)
        DEF-01 anything unexpected (default deny)
  ASK   ALW-01 new recipient             LIM-02 over the auto limit     VEL-01 too many actions too fast
  ALLOW only when no rule above fired.

Design choices that close loopholes:
  * SNAPSHOT: the request, plan and simulation are copied once, with strict type checks, before any rule runs.
    Every rule then sees the same values (an object that changes between reads cannot fool the checks).
  * Numbers come from the CALLDATA (what would really be signed, via wallet_engine/binding.py) and must match
    the request to the last digit. The calldata itself must be plain hex (no spaces, underscores, odd digits).
  * Only OUR token contract (TOKEN_ADDRESS in .env) may be used (limits are in TUSD with 18 decimals).
  * confirm() only works for a request that evaluate() really answered "ask", once, within a few minutes,
    and for the very same transaction.
  * Approvals count as potential spending. Calls run one at a time (a lock). No audit entry, no money.
  * Text that comes from outside (amounts, revert messages, origins) is cleaned before it is put in a reason
    or a log entry: no line breaks, no hidden characters, short.
  * Only requests from a TRUSTED origin count towards the velocity rule, so outsiders cannot throttle the owner.
"""
import os
import re
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
MAX_FIELD_CHARS = 200                     # longer text in a request is refused
MAX_CALLDATA_CHARS = 2 + 8 + 128          # selector + two 32-byte arguments

DENY, ASK = "deny", "ask"

_ID_RE = re.compile(r"[A-Za-z0-9_.:\-]{1,128}")
_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_HEX_RE = re.compile(r"0x[0-9a-fA-F]*")
_BURN_ADDRESSES = {"0x" + "0" * 40, "0x000000000000000000000000000000000000dead"}

_LOCK = threading.RLock()
_PENDING = {}                             # request_id -> (what was asked, deadline)


def reset() -> None:
    """Forget open questions (used by tests)."""
    with _LOCK:
        _PENDING.clear()


# ------------------------------------------------------------------ small helpers

def _clean(text, limit: int = 60) -> str:
    """Make outside text safe to show: printable characters only (no line breaks, no hidden or reversing
    characters), shortened. Used for anything that did not come from our own code."""
    text = str(text)
    text = "".join(ch if ch.isprintable() else "?" for ch in text[: limit * 4])
    return text if len(text) <= limit else text[:limit] + "..."


def _norm(address) -> str:
    return str(address).strip().lower()


def _allowlist(rules: dict) -> set:
    return {_norm(a) for a in rules["allowlist"]}


def _allowed_tokens() -> set:
    """The only token contract this wallet may touch: TOKEN_ADDRESS from .env (must be a well-formed address)."""
    value = os.getenv("TOKEN_ADDRESS", "").strip()
    return {value.lower()} if _ADDRESS_RE.fullmatch(value) else set()


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
        if not isinstance(amount, str) or not re.fullmatch(r"[0-9]+(\.[0-9]+)?", amount):
            return None
        raw = Decimal(amount).scaleb(TOKEN_DECIMALS)
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


# ------------------------------------------------------------------ snapshots (read each thing ONCE, strictly)

def _snapshot_request(req):
    """Return (ActionRequest copy, None) or (None, (request_id, reason)) if it cannot be used safely."""
    if not isinstance(req, ActionRequest):
        return None, ("unknown", "The request was not in a form the firewall understands, so it is refused by default.")
    try:
        rid, action, token, to, amount, unlimited, origin = (req.request_id, req.action, req.token, req.to,
                                                              req.amount, req.unlimited, req.origin)
    except Exception:
        return None, ("unknown", "The request could not be read, so it is refused by default.")
    if type(rid) is not str or not _ID_RE.fullmatch(rid):
        return None, ("unknown", "The request has no usable id (letters, digits and _ . : - only), so it is refused.")
    if not (type(action) is str and type(token) is str and type(to) is str and type(amount) is str and type(unlimited) is bool):
        return None, (rid, "Some fields of the request have the wrong type, so it is refused by default.")
    if max(len(action), len(token), len(to), len(amount)) > MAX_FIELD_CHARS:
        return None, (rid, "Some fields of the request are far too long, so it is refused by default.")
    if type(origin) is not str or len(origin) > MAX_FIELD_CHARS:
        origin = ""                                  # unusable origin -> untrusted (PRV-01)
    return ActionRequest(rid, action, token, to, amount, unlimited, origin), None


def _snapshot_plan(plan) -> Optional[TxPlan]:
    if not isinstance(plan, TxPlan):
        return None
    try:
        return TxPlan(chain_id=plan.chain_id, from_addr=plan.from_addr, to=plan.to, value=plan.value, data=plan.data,
                      gas=plan.gas, function=plan.function, args=plan.args, summary=plan.summary)
    except Exception:
        return None


def _snapshot_sim(sim):
    """Return (ok, revert_reason, outflow) with strict types, or None if unusable."""
    if not isinstance(sim, SimResult):
        return None
    try:
        ok, why, outflow = sim.ok, sim.revert_reason, sim.outflow
    except Exception:
        return None
    return ok, why, outflow


# ------------------------------------------------------------------ the checks

def _assess(req: ActionRequest, plan, sim, confirming: bool):
    """Run every rule on SNAPSHOTS. Returns (findings, binding). findings = [(rule_id, 'deny'|'ask', reason), ...]."""
    rules = state.load_rules()
    allowed = _allowlist(rules)
    findings = []

    def add(rule_id, level, reason):
        findings.append((rule_id, level, reason))

    # PRV-01: where did the request come from?
    hit = provenance.check(req, rules["trusted_origins"])
    if hit:
        add(hit[0], DENY, hit[1])

    # KIL-01: emergency stop
    if state.kill_switch_on():
        add("KIL-01", DENY, "The kill switch is ON, so the wallet is frozen and cannot send anything.")

    plan = _snapshot_plan(plan)
    if plan is None:
        add("DEF-01", DENY, "There is no usable transaction plan to check, so the request is refused by default.")
        return findings, None

    # NET-01: right network? (a plain integer, equal to the expected one)
    expected = _expected_chain_id(rules)
    if expected is None:
        add("NET-01", DENY, "The wallet could not confirm which network it is on, so it refuses to act.")
    elif type(plan.chain_id) is not int or plan.chain_id != expected:
        shown = plan.chain_id if type(plan.chain_id) is int else "unreadable"
        add("NET-01", DENY, f"This transaction is for network {shown}, but the wallet is set up for network {expected}.")

    # The calldata must be plain hex before anything reads it (the parser behind binding is more forgiving
    # than the signer: it accepts underscores, spaces and non-ASCII digits).
    data = plan.data
    if type(data) is not str or len(data) > MAX_CALLDATA_CHARS or not _HEX_RE.fullmatch(data):
        add("SIM-01", DENY, "The transaction data is not plain hexadecimal, so it is refused.")
        return findings, None
    try:
        binding = token_binding(plan)
    except ValueError as exc:
        add("SIM-01", DENY, f"The transaction data could not be understood ({_clean(exc)}), so it is refused.")
        return findings, None

    raw = int(binding["amount"])
    real_action = binding["action"]
    unlimited = real_action == "approve" and raw >= UNLIMITED_FROM
    real_amount = Decimal(raw).scaleb(-TOKEN_DECIMALS)

    # TOK-01: only our own token contract
    ours = _allowed_tokens()
    if not ours:
        add("TOK-01", DENY, "No token contract is configured (TOKEN_ADDRESS), so the wallet refuses to act.")
    elif binding["token"] not in ours or req.token.lower() not in ours:
        add("TOK-01", DENY, f"{_short(binding['token'])} is not the wallet's own token. Only TestUSD may be moved.")

    # SIM-01 (part 1): does the real transaction match what was asked, to the last digit?
    problems = []
    if type(plan.value) is not int or plan.value != 0:
        problems.append("it also tries to send native coin (ETH)")
    if real_action != req.action:
        problems.append(f"it would {real_action}, not {_clean(req.action, 20)}")
    if not _ADDRESS_RE.fullmatch(req.token) or binding["token"] != req.token.lower():
        problems.append("it uses a different token contract")
    if not _ADDRESS_RE.fullmatch(req.to) or binding["to"] != req.to.lower():
        problems.append("it goes to a different address")
    if real_action in ("transfer", "approve") and not unlimited:
        if _to_raw(req.amount) != raw:
            problems.append(f"the amount is {real_amount}, not {_clean(req.amount, 30)}")
    if unlimited != req.unlimited:
        problems.append("the unlimited flag does not match the transaction")
    if problems:
        add("SIM-01", DENY, "The transaction does not match the request: " + "; ".join(problems) + ".")

    # SIM-01 (part 2): did the dry run work, and does it move no more than asked?
    if not confirming:
        result = _snapshot_sim(sim)
        if result is None or result[0] is not True:
            why = _clean(result[1]) if result and isinstance(result[1], str) and result[1] else "no usable simulation result"
            add("SIM-01", DENY, f"The dry run failed ({why}), so the transaction would not work as expected.")
        else:
            try:
                if type(result[2]) is not str or not re.fullmatch(r"[0-9]+(\.[0-9]+)?", result[2]):
                    raise ValueError("outflow is not a plain non-negative number")
                outflow = Decimal(result[2])
                if real_action == "transfer" and outflow > Decimal(req.amount):
                    add("SIM-01", DENY, f"The dry run shows {_clean(result[2], 30)} leaving the wallet, more than the {_clean(req.amount, 30)} requested.")
                elif real_action != "transfer" and outflow != 0:
                    add("SIM-01", DENY, "The dry run shows tokens leaving the wallet during an approval, which should never happen.")
            except Exception:
                add("SIM-01", DENY, "The dry run reported an amount that could not be read.")

    # Action-specific rules
    if real_action == "transfer":
        target = binding["to"]
        if target in _BURN_ADDRESSES or target == binding["token"]:
            add("DST-01", DENY, f"{_short(target)} is a burn address or the token contract itself; tokens sent there are lost for good.")
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


def _log(req: ActionRequest, decision: Decision, strict: bool = False) -> None:
    """Write the decision to the audit log. Best effort, unless strict (then a failure is raised).
    Only cleaned, short values are written."""
    event = {"event": "DECISION", "request_id": req.request_id, "action": _clean(req.action, 20),
             "origin": provenance.describe(req.origin), "decision": decision.decision, "rule_ids": list(decision.rule_ids)}
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
    if outcome == "allow" and binding is None:                     # cannot happen, but "allow" needs proof
        findings, outcome = [("DEF-01", DENY, "There is nothing to approve, so the request is refused by default.")], DENY
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
        try:
            with localcontext(Context(prec=120)):
                state.record_spend(Decimal(binding["amount"]).scaleb(-TOKEN_DECIMALS))
        except Exception:
            decision = _deny(req.request_id, "DEF-01", "The spending could not be written to the spending record, so nothing is allowed (no record, no money).")
            _log(req, decision)
            return decision
    return decision


def _prune_pending(now: float) -> None:
    for rid in [r for r, (_, deadline) in _PENDING.items() if deadline < now]:
        del _PENDING[rid]
    while len(_PENDING) > MAX_PENDING:
        del _PENDING[next(iter(_PENDING))]


def evaluate(req: ActionRequest, plan: Optional[TxPlan] = None, sim: Optional[SimResult] = None) -> Decision:
    snap, problem = _snapshot_request(req)
    if snap is None:
        return _deny(problem[0], "DEF-01", problem[1])
    try:
        with _LOCK:
            findings, binding = _safe_assess(snap, plan, sim, confirming=False)
            if not any(rule == provenance.RULE_ID for rule, _, _ in findings):
                state.record_action()      # only a TRUSTED origin counts toward VEL-01 (outsiders cannot throttle the owner)
            now = time.time()
            _prune_pending(now)
            _PENDING.pop(snap.request_id, None)
            decision = _finish(snap, findings, binding, "Every safety check passed.")
            if decision.decision == ASK and binding is not None:
                _PENDING[snap.request_id] = (_fingerprint(binding), now + CONFIRM_WINDOW_SECONDS)
            return decision
    except Exception as exc:               # last line of defence: evaluate never raises and never allows on error
        return _deny(snap.request_id, "DEF-01", f"The firewall hit an unexpected problem ({type(exc).__name__}), so it refuses by default.")

def preview(req: ActionRequest, plan: Optional[TxPlan] = None, sim: Optional[SimResult] = None) -> Decision:
    """What evaluate() would answer right now, with NO side effects (for the Preview screen).

    Same rules as evaluate(), but it does not count the request toward VEL-01, does not record any spending,
    does not issue an approval token, does not open a confirmation question and does not write to the audit log.
    Calling it any number of times changes nothing, and its answer can never be used to send money.
    """
    snap, problem = _snapshot_request(req)
    if snap is None:
        return _deny(problem[0], "DEF-01", problem[1])
    try:
        with _LOCK:
            findings, binding = _safe_assess(snap, plan, sim, confirming=False)
            outcome = _decide(findings)
            if outcome == "allow" and binding is None:                 # cannot happen, but "allow" needs proof
                return _deny(snap.request_id, "DEF-01", "There is nothing to approve, so the request is refused by default.")
            if outcome == "allow":
                return Decision(request_id=snap.request_id, decision="allow", rule_ids=["ALLOW"],
                                reasons=["Every safety check passed."], approval_token=None)
            return Decision(request_id=snap.request_id, decision=outcome, rule_ids=[r for r, _, _ in findings],
                            reasons=[text for _, _, text in findings], approval_token=None)
    except Exception as exc:               # never raises, never allows on an error
        return _deny(snap.request_id, "DEF-01", f"The firewall hit an unexpected problem ({type(exc).__name__}), so it refuses by default.")
def confirm(req: ActionRequest, plan: Optional[TxPlan] = None) -> Decision:
    snap, problem = _snapshot_request(req)
    if snap is None:
        return _deny(problem[0], "DEF-01", problem[1])
    try:
        with _LOCK:
            findings, binding = _safe_assess(snap, plan, None, confirming=True)
            findings = [f for f in findings if f[1] == DENY]       # the person already accepted the "ask" reasons

            # CNF-01: there must be an open question for exactly this transaction
            now = time.time()
            _prune_pending(now)
            waiting = _PENDING.get(snap.request_id)
            if waiting is None:
                findings.append(("CNF-01", DENY, "Nobody was asked about this request (or the question expired), so it cannot be confirmed."))
            elif binding is None or waiting[0] != _fingerprint(binding):
                findings.append(("CNF-01", DENY, "The transaction being confirmed is not the one the person was asked about."))

            decision = _finish(snap, findings, binding, "You confirmed this action and the hard safety checks still pass.")
            if decision.decision == "allow":
                _PENDING.pop(snap.request_id, None)                  # a question can be answered only once
            return decision
    except Exception as exc:
        return _deny(snap.request_id, "DEF-01", f"The firewall hit an unexpected problem ({type(exc).__name__}), so it refuses by default.")