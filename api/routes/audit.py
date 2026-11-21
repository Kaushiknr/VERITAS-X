"""Audit Trail and Cryptographic Ledger APIs for VERITAS-X."""
import uuid
from typing import Dict, Any, Optional
from fastapi import APIRouter, Query
from audit.ledger import audit_ledger

router = APIRouter(prefix="/audit", tags=["audit"])

@router.get("")
def list_audit_events(
    case_id: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
) -> Dict[str, Any]:
    events = audit_ledger.get_events(case_id=case_id, limit=limit)
    return {"success": True, "data": [e.model_dump() for e in events], "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.post("/verify")
def verify_audit_ledger() -> Dict[str, Any]:
    is_valid, error_msg, count = audit_ledger.verify_ledger_integrity()
    return {
        "success": True,
        "data": {
            "chain_valid": is_valid,
            "total_blocks_verified": count,
            "error_detail": error_msg,
            "status": "SECURE_IMMUTABLE" if is_valid else "COMPROMISED",
        },
        "request_id": f"req_{uuid.uuid4().hex[:8]}",
    }
