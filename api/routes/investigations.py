"""Investigation Intelligence, Timeline, EGA and Correlation APIs for VERITAS-X."""
import uuid
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Query
from core.case_store import case_store
from playbooks.schema import playbook_loader
from indexing.engine import search_engine
from engine.ega import ega_engine
from engine.correlation import correlation_engine
from audit.ledger import audit_ledger

router = APIRouter(prefix="/investigations", tags=["investigations"])

@router.get("/{case_id}/events")
def search_investigation_events(
    case_id: str,
    q: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    device_type: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    limit: int = Query(200, le=1000),
) -> Dict[str, Any]:
    events = search_engine.search_events(
        case_id=case_id,
        query_text=q,
        event_type=event_type,
        device_type=device_type,
        username=username,
        start_time_utc=start_time,
        end_time_utc=end_time,
        limit=limit,
    )
    return {"success": True, "data": [e.model_dump() for e in events], "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.get("/{case_id}/timeline")
def get_timeline(case_id: str, limit: int = Query(300, le=2000)) -> Dict[str, Any]:
    events = search_engine.search_events(case_id=case_id, limit=limit, sort_asc=True)
    return {
        "success": True,
        "data": {
            "case_id": case_id,
            "total_events": len(events),
            "events": [e.model_dump() for e in events],
        },
        "request_id": f"req_{uuid.uuid4().hex[:8]}",
    }

@router.get("/{case_id}/coverage")
def get_evidence_coverage(
    case_id: str,
    playbook_id: str = Query("usb_data_exfiltration"),
) -> Dict[str, Any]:
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail={"code": "CASE_NOT_FOUND", "message": f"Case {case_id} not found"})

    playbook = playbook_loader.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail={"code": "PLAYBOOK_NOT_FOUND", "message": f"Playbook {playbook_id} not found"})

    events = search_engine.search_events(case_id=case_id, limit=5000)
    evidence_items = case_store.list_case_evidence(case_id)

    result = ega_engine.evaluate_coverage(
        case_id=case_id,
        playbook=playbook,
        events=events,
        collected_evidence=evidence_items,
    )

    audit_ledger.append_event(
        case_id=case_id,
        actor_id="investigator_local",
        action="evidence_coverage_evaluated",
        target_id=playbook_id,
        details={"coverage_score": result.coverage_score, "playbook": playbook_id},
    )

    return {"success": True, "data": result.model_dump(), "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.get("/{case_id}/correlations")
def get_correlations(
    case_id: str,
    window_seconds: float = Query(300.0, ge=10.0, le=3600.0),
) -> Dict[str, Any]:
    events = search_engine.search_events(case_id=case_id, limit=2000)
    correlations = correlation_engine.correlate_events(events, max_window=window_seconds)

    return {
        "success": True,
        "data": {
            "case_id": case_id,
            "correlation_count": len(correlations),
            "window_seconds": window_seconds,
            "correlations": [c.model_dump() for c in correlations],
        },
        "request_id": f"req_{uuid.uuid4().hex[:8]}",
    }

@router.get("/{case_id}/stats")
def get_investigation_stats(case_id: str) -> Dict[str, Any]:
    stats = search_engine.aggregate_events(case_id)
    evidence_items = case_store.list_case_evidence(case_id)
    claims = case_store.list_claims(case_id)

    return {
        "success": True,
        "data": {
            "case_id": case_id,
            "evidence_count": len(evidence_items),
            "events_count": stats["total_events"],
            "claims_count": len(claims),
            "by_type": stats["by_type"],
            "by_category": stats["by_category"],
        },
        "request_id": f"req_{uuid.uuid4().hex[:8]}",
    }
