"""Approval endpoints: the human gate. The ONLY way a plan gets approved is an HTTP request from the UI."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..v2 import runner
from ..v2.stages import s08_remedies
from .routes_workspaces import _ws, submit

router = APIRouter(prefix="/api")


class DecisionIn(BaseModel):
    decision: str
    approver: str
    plan_hash: str
    note: str = ""


@router.post("/ws/{ws_id}/plans/{plan_id}/decision")
def decide(ws_id: str, plan_id: str, body: DecisionIn):
    ws = _ws(ws_id)
    try:
        plan = s08_remedies.record_decision(ws, plan_id, body.decision, body.approver, body.plan_hash, body.note)
    except LookupError as e:
        raise HTTPException(404, str(e)) from None
    except PermissionError as e:
        raise HTTPException(409, str(e)) from None
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    return plan


@router.post("/ws/{ws_id}/remedies/send-to-sandbox")
def send(ws_id: str):
    ws = _ws(ws_id)
    try:
        aset = s08_remedies.freeze_approved(ws)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    submit(ws, runner.run_stage, ws, "verify", {})
    return {"sent": aset}
