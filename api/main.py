"""Sentinel Wallet REST API with server-authoritative execution and confirmation."""
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
from shared.types import ActionRequest
from wallet_engine import chain

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
        unlimited=body.unlimited, origin="user_chat",
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


class PlanRequest(BaseModel):
    action: Literal["transfer", "approve", "revoke"]
    to: str = Field(..., min_length=1, description="Recipient or spender")
    amount: str = "0"
    unlimited: bool = False


class ConfirmRequest(BaseModel):
    request_id: str = Field(..., min_length=1)


@app.post("/api/plan")
def plan(body: PlanRequest):
    """Preview only. If the firewall asks, retain the request server-side for confirmation."""
    req = _request(body)
    try:
        tx_plan, sim, decision = _plan_simulate_evaluate(req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Cannot build or evaluate transaction ({type(exc).__name__}).") from exc
    if decision.decision == "ask":
        _remember_ask(req)
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
