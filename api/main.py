"""Sentinel Wallet REST API with server-authoritative execution and confirmation.

Run from the repo root:   uvicorn api.main:app --reload --port 8000
Docs (auto-generated):    http://127.0.0.1:8000/docs

The frontend (ui/) calls these endpoints through the Vite proxy (/api -> :8000).

Endpoints that matter for safety:
  POST /api/plan     PREVIEW ONLY. Builds + simulates + asks firewall.preview(), which has no side effects
                     (it does not count as spending, does not issue a token, cannot be confirmed).
  POST /api/execute  Re-runs plan -> simulate -> firewall.evaluate() on the SERVER (a browser-supplied
                     decision is ignored), then sends only if the answer is "allow". An "ask" is remembered
                     on the server and must be confirmed separately.
  POST /api/confirm  The human confirmation step for a server-remembered "ask" (firewall.confirm()).
"""
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

import firewall
import wallet_engine
from agent import llm
from agent import handle_message as handle_agent_message, confirm_pending as confirm_agent_pending, has_pending_confirmation
from shared.types import ActionRequest
from wallet_engine import chain
from firewall import audit, state

app = FastAPI(title="Sentinel Wallet API", version="0.2.0")
_CONFIRM_TTL_SECONDS = 600
_MAX_PENDING_CONFIRMATIONS = 1000
_PENDING_LOCK = threading.RLock()


@dataclass
class _PendingConfirmation:
    request: ActionRequest
    created_at: float


_PENDING_CONFIRMATIONS: dict[str, _PendingConfirmation] = {}


def _jsonable(obj):
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, int) and not isinstance(obj, bool) and abs(obj) > 2**53:
        return str(obj)
    return obj


def _prune_pending(now: float) -> None:
    for rid in [rid for rid, item in _PENDING_CONFIRMATIONS.items()
                if now - item.created_at > _CONFIRM_TTL_SECONDS]:
        _PENDING_CONFIRMATIONS.pop(rid, None)
    while len(_PENDING_CONFIRMATIONS) > _MAX_PENDING_CONFIRMATIONS:
        oldest = min(_PENDING_CONFIRMATIONS, key=lambda rid: _PENDING_CONFIRMATIONS[rid].created_at)
        _PENDING_CONFIRMATIONS.pop(oldest, None)


def _remember_ask(req: ActionRequest) -> None:
    with _PENDING_LOCK:
        now = time.monotonic()
        _prune_pending(now)
        _PENDING_CONFIRMATIONS[req.request_id] = _PendingConfirmation(req, now)
        _prune_pending(now)


def _take_pending(request_id: str) -> ActionRequest | None:
    with _PENDING_LOCK:
        _prune_pending(time.monotonic())
        item = _PENDING_CONFIRMATIONS.pop(request_id, None)
        return item.request if item else None


def _request(body: "PlanRequest", request_id: str | None = None) -> ActionRequest:
    return ActionRequest(
        request_id=request_id or str(uuid.uuid4()), action=body.action,
        token=chain.token_address(), to=body.to, amount=body.amount,
        unlimited=body.unlimited,
        origin="user_chat",   # set by CODE from the channel (the UI form), never by an LLM
    )


def _plan_simulate_evaluate(req: ActionRequest):
    tx_plan = wallet_engine.plan(req)
    sim = wallet_engine.simulate(tx_plan)
    decision = firewall.evaluate(req, tx_plan, sim)
    return tx_plan, sim, decision


def _explorer_url(tx_hash: str | None) -> str | None:
    if tx_hash and chain.network().lower() == "sepolia":
        return f"https://sepolia.etherscan.io/tx/{tx_hash}"
    return None


def _execute_result(req, tx_plan, decision):
    if decision.decision == "deny":
        return _jsonable({"status": "denied", "decision": asdict(decision),
                          "reasons": decision.reasons, "tx_hash": None, "executed": False})
    if decision.decision == "ask":
        _remember_ask(req)
        return _jsonable({"status": "awaiting_confirmation", "request_id": req.request_id,
                          "decision": asdict(decision), "reasons": decision.reasons,
                          "tx_hash": None, "executed": False})
    if decision.decision != "allow":
        raise HTTPException(status_code=503, detail="Firewall returned an unknown decision; execution refused.")
    try:
        tx_hash = wallet_engine.execute(tx_plan, decision)
    except wallet_engine.ExecutionRefused as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except wallet_engine.ExecutionFailed as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Transaction execution failed ({type(exc).__name__}).") from exc
    return _jsonable({"status": "executed", "decision": asdict(decision),
                      "reasons": decision.reasons, "tx_hash": tx_hash,
                      "explorer_url": _explorer_url(tx_hash), "executed": True})


class PlanRequest(BaseModel):
    action: Literal["transfer", "approve", "revoke"]
    to: str = Field(..., min_length=1, description="Recipient or spender")
    amount: str = "0"
    unlimited: bool = False


class ConfirmRequest(BaseModel):
    request_id: str = Field(..., min_length=1)


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)


class KillSwitchRequest(BaseModel):
    enabled: bool



@app.post("/api/chat")
def chat(body: ChatRequest):
    """Send a user-authored message through the protected agent; never accept a decision from the client."""
    try:
        reply = handle_agent_message(body.message, origin="user_chat")
        result = asdict(reply)
        if reply.decision is not None and reply.decision.decision == "ask":
            result["status"] = "awaiting_confirmation"
            result["request_id"] = reply.decision.request_id
        elif reply.decision is not None and reply.decision.decision == "deny":
            result["status"] = "denied"
        elif reply.tx_hash:
            result["status"] = "executed"
            result["explorer_url"] = _explorer_url(reply.tx_hash)
        else:
            result["status"] = "blocked" if reply.blocked else "completed"
        return _jsonable(result)
    except Exception:
        raise HTTPException(status_code=503, detail="The agent could not safely process that message. Please try again.") from None


@app.get("/api/security")
def security_status():
    try:
        return {"kill_switch_on": state.kill_switch_on()}
    except Exception:
        return {"kill_switch_on": True, "warning": "Kill-switch state could not be verified; wallet treated as frozen."}


@app.post("/api/kill-switch")
def set_kill_switch(body: KillSwitchRequest):
    try:
        state.set_kill_switch(body.enabled)
        return {"kill_switch_on": state.kill_switch_on()}
    except Exception:
        raise HTTPException(status_code=503, detail="Could not safely update the kill switch. The wallet remains frozen if state is uncertain.") from None


@app.get("/api/audit")
def audit_log(limit: int = 50):
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=422, detail="Limit must be between 1 and 200.")
    try:
        check = audit.check()
        entries = audit.tail(limit)
        return {"entries": entries, "integrity": {"ok": check.ok, "count": check.entries,
                "head": check.head, "reason": check.reason, "line": check.line}}
    except Exception:
        raise HTTPException(status_code=503, detail="The audit log could not be read safely.") from None


@app.get("/api/health")
def health():
    return {"backend": "ok", "chain": chain.status(), "llm": llm.config_status()}


@app.get("/api/wallet")
def wallet():
    try:
        return {"address": chain.wallet_address(), "token": chain.token_address(),
                "balances": wallet_engine.balances(), "approvals": wallet_engine.approvals()}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Cannot read wallet: {exc}")


@app.post("/api/plan")
def plan(body: PlanRequest):
    """Preview only. Nothing is sent, nothing is counted, nothing is remembered.

    firewall.preview() answers like evaluate() but has no side effects, so any number of previews
    leaves the daily cap, the velocity counter and the confirmation list untouched. An "ask" shown
    here can NOT be confirmed: the person must press Execute, and the server then asks the question.
    """
    req = _request(body)
    try:
        tx_plan = wallet_engine.plan(req)
        sim = wallet_engine.simulate(tx_plan)
        decision = firewall.preview(req, tx_plan, sim)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Cannot build or evaluate transaction ({type(exc).__name__}).") from exc
    return _jsonable({"request": asdict(req), "plan": asdict(tx_plan),
                      "simulation": asdict(sim), "decision": asdict(decision), "executed": False})


@app.post("/api/execute")
def execute(body: PlanRequest):
    """Ignore browser decisions; rebuild, simulate and evaluate from request details on the server."""
    req = _request(body)
    try:
        tx_plan, _sim, decision = _plan_simulate_evaluate(req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Cannot build or evaluate transaction ({type(exc).__name__}).") from exc
    return _execute_result(req, tx_plan, decision)


@app.post("/api/confirm")
def confirm(body: ConfirmRequest):
    """Confirm only a server-remembered ask. Browser cannot supply a plan or decision."""
    req = _take_pending(body.request_id)
    if req is None:
        # Chat-originated ask requests are remembered by the protected agent, not this endpoint's plan flow.
        if not has_pending_confirmation(body.request_id):
            raise HTTPException(status_code=404, detail="Confirmation is missing, expired, or already used.")
        reply = confirm_agent_pending(body.request_id)
        if reply.decision is not None:
            result = asdict(reply)
            if reply.tx_hash:
                result["status"] = "executed"
                result["explorer_url"] = _explorer_url(reply.tx_hash)
            else:
                result["status"] = "denied" if reply.decision.decision == "deny" else "blocked"
            return _jsonable(result)
        raise HTTPException(status_code=404, detail="Confirmation is missing, expired, or already used.")
    try:
        tx_plan = wallet_engine.plan(req)
        decision = firewall.confirm(req, tx_plan)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Cannot confirm transaction ({type(exc).__name__}).") from exc
    if decision.decision != "allow":
        return _jsonable({"status": "denied", "decision": asdict(decision),
                          "reasons": decision.reasons, "tx_hash": None, "executed": False})
    try:
        tx_hash = wallet_engine.execute(tx_plan, decision)
    except wallet_engine.ExecutionRefused as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except wallet_engine.ExecutionFailed as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Transaction execution failed ({type(exc).__name__}).") from exc
    return _jsonable({"status": "executed", "decision": asdict(decision),
                      "reasons": decision.reasons, "tx_hash": tx_hash,
                      "explorer_url": _explorer_url(tx_hash), "executed": True})


@app.get("/api/llm/status")
def llm_status():
    return llm.config_status()


@app.post("/api/llm/test")
def llm_test():
    return llm.test_connection()
