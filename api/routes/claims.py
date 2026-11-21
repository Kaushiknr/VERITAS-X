"""Claim-Aware Verification (CAV) API Routes for VERITAS-X."""
import uuid
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from core.models import Claim, ClaimAssessment
from core.case_store import case_store
from playbooks.schema import playbook_loader
from indexing.engine import search_engine
from engine.cav import cav_engine
from audit.ledger import audit_ledger

router = APIRouter(tags=["claims"])

class ClaimCreateRequest(BaseModel):
    statement: str
    claim_type: str = "usb_file_transfer"
    subject: Optional[str] = None
    object: Optional[str] = None
    target_device: Optional[str] = None

class VerificationRequest(BaseModel):
    playbook_id: str = "usb_data_exfiltration"

@router.post("/cases/{case_id}/claims")
def create_claim(case_id: str, req: ClaimCreateRequest) -> Dict[str, Any]:
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail={"code": "CASE_NOT_FOUND", "message": f"Case {case_id} not found"})

    claim_id = f"claim_{uuid.uuid4().hex[:8]}"
    claim = Claim(
        claim_id=claim_id,
        case_id=case_id,
        statement=req.statement,
        claim_type=req.claim_type,
        subject=req.subject,
        object=req.object,
        target_device=req.target_device,
    )
    created = case_store.create_claim(claim)

    audit_ledger.append_event(
        case_id=case_id,
        actor_id="investigator_local",
        action="claim_registered",
        target_id=claim_id,
        details={"statement": req.statement, "type": req.claim_type},
    )

    return {"success": True, "data": created.model_dump(), "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.get("/cases/{case_id}/claims")
def list_case_claims(case_id: str) -> Dict[str, Any]:
    claims = case_store.list_claims(case_id)
    return {"success": True, "data": [c.model_dump() for c in claims], "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.get("/claims/{claim_id}")
def get_claim_detail(claim_id: str) -> Dict[str, Any]:
    claim = case_store.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail={"code": "CLAIM_NOT_FOUND", "message": f"Claim {claim_id} not found"})
    return {"success": True, "data": claim.model_dump(), "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.post("/claims/{claim_id}/verify")
def verify_claim(claim_id: str, req: VerificationRequest) -> Dict[str, Any]:
    claim = case_store.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail={"code": "CLAIM_NOT_FOUND", "message": f"Claim {claim_id} not found"})

    playbook = playbook_loader.get_playbook(req.playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail={"code": "PLAYBOOK_NOT_FOUND", "message": f"Playbook {req.playbook_id} not found"})

    events = search_engine.search_events(case_id=claim.case_id, limit=5000)

    # Execute deterministic CAV algorithm
    assessment = cav_engine.verify_claim(claim, playbook, events)

    # Persist assessment
    case_store.save_assessment(assessment)

    # Audit event
    audit_ledger.append_event(
        case_id=claim.case_id,
        actor_id="investigator_local",
        action="claim_verified",
        target_id=claim_id,
        details={
            "assessment_id": assessment.assessment_id,
            "status": assessment.status,
            "supporting_count": len(assessment.supporting_evidence),
            "unresolved": assessment.unresolved_requirements,
        },
    )

    return {"success": True, "data": assessment.model_dump(), "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.get("/claims/{claim_id}/assessments")
def get_claim_assessments(claim_id: str) -> Dict[str, Any]:
    assessments = case_store.list_assessments(claim_id)
    return {"success": True, "data": [a.model_dump() for a in assessments], "request_id": f"req_{uuid.uuid4().hex[:8]}"}
