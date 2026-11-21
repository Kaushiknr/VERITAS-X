"""Evidence Acquisition, Integrity and Reprocessing APIs for VERITAS-X."""
import uuid
from pathlib import Path
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from core.models import CanonicalEvidence, generate_utc_timestamp
from core.case_store import case_store
from vault.storage import vault
from parsers import parse_evidence_file
from indexing.engine import search_engine
from audit.ledger import audit_ledger

router = APIRouter(tags=["evidence"])

@router.post("/cases/{case_id}/evidence")
async def upload_evidence(
    case_id: str,
    file: UploadFile = File(...),
    acquired_by: str = Form("investigator_001"),
    source_system: str = Form("FORENSIC-WORKSTATION"),
    acquisition_method: str = Form("authorized_export"),
) -> Dict[str, Any]:
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail={"code": "CASE_NOT_FOUND", "message": f"Case {case_id} not found"})

    evidence_id = f"ev_{uuid.uuid4().hex[:8]}"
    clean_filename = Path(file.filename or "evidence.bin").name
    file_bytes = await file.read()

    # 1. Store in immutable vault with pre/post SHA-256 verification
    try:
        canonical_ev = vault.store_evidence(
            case_id=case_id,
            evidence_id=evidence_id,
            filename=clean_filename,
            file_bytes=file_bytes,
            acquired_by=acquired_by,
            source_system=source_system,
            file_type=file.content_type or "application/octet-stream",
            acquisition_method=acquisition_method,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail={"code": "VAULT_ERROR", "message": str(e)})

    # 2. Parse evidence into normalized events
    vault_file_path = vault.get_vault_file_path(case_id, evidence_id, clean_filename)
    run_id = f"run_{uuid.uuid4().hex[:8]}"
    events = parse_evidence_file(
        file_path=vault_file_path,
        filename=clean_filename,
        case_id=case_id,
        evidence_id=evidence_id,
        extraction_run_id=run_id,
        options={"timezone": case.timezone},
    )

    # 3. Update evidence processing & provenance
    canonical_ev.processing.status = "completed"
    canonical_ev.processing.processing_run_id = run_id
    canonical_ev.processing.processed_at = generate_utc_timestamp()
    if events:
        canonical_ev.processing.parser = events[0].source.parser
        canonical_ev.processing.parser_version = events[0].source.parser_version

    canonical_ev.provenance.source_record_count = len(events)
    canonical_ev.provenance.derived_record_count = len(events)

    # 4. Save metadata to authoritative store
    case_store.register_evidence(canonical_ev)

    # 5. Index events & evidence in search engine
    if events:
        search_engine.bulk_index_events(events)
    search_engine.index_evidence_metadata(canonical_ev)

    # 6. Audit event
    audit_ledger.append_event(
        case_id=case_id,
        actor_id=acquired_by,
        action="evidence_acquired_and_parsed",
        target_id=evidence_id,
        details={
            "filename": clean_filename,
            "sha256": canonical_ev.acquisition.original_sha256,
            "parsed_records": len(events),
        },
    )

    return {
        "success": True,
        "data": {
            "evidence": canonical_ev.model_dump(),
            "indexed_events_count": len(events),
        },
        "request_id": f"req_{uuid.uuid4().hex[:8]}",
    }

@router.get("/cases/{case_id}/evidence")
def list_case_evidence(case_id: str) -> Dict[str, Any]:
    items = case_store.list_case_evidence(case_id)
    return {"success": True, "data": [e.model_dump() for e in items], "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.get("/evidence/{evidence_id}")
def get_evidence_detail(evidence_id: str) -> Dict[str, Any]:
    ev = case_store.get_evidence(evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail={"code": "EVIDENCE_NOT_FOUND", "message": f"Evidence {evidence_id} not found"})
    return {"success": True, "data": ev.model_dump(), "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.post("/evidence/{evidence_id}/verify")
def verify_evidence_integrity(evidence_id: str) -> Dict[str, Any]:
    ev = case_store.get_evidence(evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail={"code": "EVIDENCE_NOT_FOUND", "message": f"Evidence {evidence_id} not found"})

    valid, current_hash = vault.verify_vault_file(
        ev.case_id, ev.evidence_id, ev.identity.original_filename, ev.acquisition.original_sha256
    )

    ev.integrity.status = "verified" if valid else "mismatch"
    ev.integrity.verified_at = generate_utc_timestamp()
    case_store.register_evidence(ev)

    audit_ledger.append_event(
        case_id=ev.case_id,
        actor_id="investigator_local",
        action="evidence_integrity_verified",
        target_id=evidence_id,
        result="success" if valid else "failure",
        details={"expected_sha256": ev.acquisition.original_sha256, "computed_sha256": current_hash},
    )

    return {
        "success": True,
        "data": {
            "evidence_id": evidence_id,
            "integrity_verified": valid,
            "baseline_sha256": ev.acquisition.original_sha256,
            "current_sha256": current_hash,
            "status": ev.integrity.status,
        },
        "request_id": f"req_{uuid.uuid4().hex[:8]}",
    }

@router.post("/evidence/{evidence_id}/reprocess")
def reprocess_evidence(evidence_id: str) -> Dict[str, Any]:
    ev = case_store.get_evidence(evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail={"code": "EVIDENCE_NOT_FOUND", "message": f"Evidence {evidence_id} not found"})

    case = case_store.get_case(ev.case_id)
    vault_file_path = vault.get_vault_file_path(ev.case_id, ev.evidence_id, ev.identity.original_filename)
    run_id = f"run_{uuid.uuid4().hex[:8]}"

    events = parse_evidence_file(
        file_path=vault_file_path,
        filename=ev.identity.original_filename,
        case_id=ev.case_id,
        evidence_id=ev.evidence_id,
        extraction_run_id=run_id,
        options={"timezone": case.timezone if case else "UTC"},
    )

    if events:
        search_engine.bulk_index_events(events)

    ev.processing.status = "completed"
    ev.processing.processing_run_id = run_id
    ev.processing.processed_at = generate_utc_timestamp()
    ev.provenance.derived_record_count = len(events)
    case_store.register_evidence(ev)

    audit_ledger.append_event(
        case_id=ev.case_id,
        actor_id="investigator_local",
        action="evidence_reprocessed",
        target_id=evidence_id,
        details={"run_id": run_id, "reprocessed_records": len(events)},
    )

    return {
        "success": True,
        "data": {
            "evidence_id": evidence_id,
            "processing_run_id": run_id,
            "reprocessed_records": len(events),
        },
        "request_id": f"req_{uuid.uuid4().hex[:8]}",
    }
