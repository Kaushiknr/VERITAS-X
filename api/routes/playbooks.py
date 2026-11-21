"""Playbook API Routes for VERITAS-X."""
import uuid
from typing import Dict, Any
from fastapi import APIRouter, HTTPException
from playbooks.schema import playbook_loader

router = APIRouter(prefix="/playbooks", tags=["playbooks"])

@router.get("")
def list_playbooks() -> Dict[str, Any]:
    playbooks = playbook_loader.list_playbooks()
    return {
        "success": True,
        "data": [p.model_dump()["playbook"] for p in playbooks],
        "request_id": f"req_{uuid.uuid4().hex[:8]}",
    }

@router.get("/{playbook_id}")
def get_playbook(playbook_id: str) -> Dict[str, Any]:
    playbook = playbook_loader.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail={"code": "PLAYBOOK_NOT_FOUND", "message": f"Playbook {playbook_id} not found"})
    return {
        "success": True,
        "data": playbook.model_dump(),
        "request_id": f"req_{uuid.uuid4().hex[:8]}",
    }
