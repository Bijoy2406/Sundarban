"""Sentinel Wallet REST API (Person 3 owns; starting point).

Run from the repo root:   uvicorn api.main:app --reload --port 8000
Docs (auto-generated):    http://127.0.0.1:8000/docs

The frontend (ui/) calls these endpoints through the Vite proxy (/api -> :8000).
Nothing here sends a transaction yet: execute() is still a stub (Person 1, task 6).
"""
import uuid
from dataclasses import asdict
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

import firewall
import wallet_engine
from agent import llm
from shared.types import ActionRequest
from wallet_engine import chain

app = FastAPI(title="Sentinel Wallet API", version="0.1.0")


def _jsonable(obj):
    """Big integers (uint256) become strings so JavaScript does not lose precision."""
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, int) and not isinstance(obj, bool) and abs(obj) > 2**53:
        return str(obj)
    return obj


@app.get("/api/health")
def health():
    """Backend up? Chain reachable? Token deployed? LLM configured?"""
    return {"backend": "ok", "chain": chain.status(), "llm": llm.config_status()}


@app.get("/api/wallet")
def wallet():
    try:
        return {
            "address": chain.wallet_address(),
            "token": chain.token_address(),
            "balances": wallet_engine.balances(),
            "approvals": wallet_engine.approvals(),
        }
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Cannot read wallet: {exc}")


class PlanRequest(BaseModel):
    action: Literal["transfer", "approve", "revoke"]
    to: str = Field(..., description="Recipient (transfer) or spender (approve/revoke)")
    amount: str = "0"
    unlimited: bool = False


@app.post("/api/plan")
def plan(body: PlanRequest):
    """Preview: build the transaction, simulate it, ask the firewall. Nothing is sent."""
    req = ActionRequest(
        request_id=str(uuid.uuid4()),
        action=body.action,
        token=chain.token_address(),
        to=body.to,
        amount=body.amount,
        unlimited=body.unlimited,
        origin="user_chat",   # set by CODE from the channel (the UI form), never by an LLM
    )
    try:
        tx_plan = wallet_engine.plan(req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Cannot build transaction: {exc}")
    sim = wallet_engine.simulate(tx_plan)
    decision = firewall.evaluate(req, tx_plan, sim)
    return _jsonable({"request": asdict(req), "plan": asdict(tx_plan), "simulation": asdict(sim),
                      "decision": asdict(decision), "executed": False})


@app.get("/api/llm/status")
def llm_status():
    return llm.config_status()


@app.post("/api/llm/test")
def llm_test():
    return llm.test_connection()
