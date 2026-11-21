"""Reporting and Provenance Manifest APIs for VERITAS-X."""
import uuid
import json
from pathlib import Path
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel
from core.case_store import case_store
from playbooks.schema import playbook_loader
from indexing.engine import search_engine
from engine.ega import ega_engine
from reporting.report_generator import report_generator
from audit.ledger import audit_ledger

router = APIRouter(tags=["reports"])

class ReportGenerateRequest(BaseModel):
    playbook_id: str = "usb_data_exfiltration"

class ReportVerifyRequest(BaseModel):
    report_data: Dict[str, Any]

@router.post("/cases/{case_id}/reports")
def generate_case_report(case_id: str, req: ReportGenerateRequest) -> Dict[str, Any]:
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail={"code": "CASE_NOT_FOUND", "message": f"Case {case_id} not found"})

    evidence_list = case_store.list_case_evidence(case_id)
    events = search_engine.search_events(case_id=case_id, limit=5000)

    # Evaluate EGA
    ega_res = None
    pb = playbook_loader.get_playbook(req.playbook_id)
    if pb:
        ega_res = ega_engine.evaluate_coverage(case_id, pb, events, evidence_list)

    # Gather claims and latest assessments
    claims = case_store.list_claims(case_id)
    assessments = []
    for c in claims:
        ass_list = case_store.list_assessments(c.claim_id)
        if ass_list:
            assessments.append(ass_list[0])

    # Check audit ledger integrity
    chain_valid, _, count = audit_ledger.verify_ledger_integrity()

    # Generate reproducible package
    report_pkg = report_generator.generate_report(
        case=case,
        evidence_list=evidence_list,
        ega_result=ega_res,
        assessments=assessments,
        audit_chain_valid=chain_valid,
        audit_record_count=count,
    )

    audit_ledger.append_event(
        case_id=case_id,
        actor_id="investigator_local",
        action="report_generated",
        target_id=report_pkg["report_id"],
        details={"manifest_sha256": report_pkg["manifest_sha256"]},
    )

    return {"success": True, "data": report_pkg, "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.get("/reports/{report_id}")
def get_report(report_id: str) -> Dict[str, Any]:
    json_path = report_generator.reports_dir / f"{report_id}.json"
    if not json_path.exists():
        raise HTTPException(status_code=404, detail={"code": "REPORT_NOT_FOUND", "message": f"Report {report_id} not found"})
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {"success": True, "data": data, "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.get("/reports/{report_id}/download")
def download_report(report_id: str, format: str = Query("html")) -> Response:
    filename = f"{report_id}.{format}"
    file_path = report_generator.reports_dir / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail={"code": "FILE_NOT_FOUND", "message": f"Report file {filename} not found"})

    content_type = "text/html" if format == "html" else ("application/json" if format == "json" else "text/markdown")
    with open(file_path, "rb") as f:
        bytes_data = f.read()

    return Response(
        content=bytes_data,
        media_type=content_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

@router.post("/reports/{report_id}/verify")
def verify_report_manifest(report_id: str, req: Optional[ReportVerifyRequest] = None) -> Dict[str, Any]:
    json_path = report_generator.reports_dir / f"{report_id}.json"
    if not json_path.exists() and not req:
        raise HTTPException(status_code=404, detail={"code": "REPORT_NOT_FOUND", "message": f"Report {report_id} not found"})

    if req and req.report_data:
        data = req.report_data
    else:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

    claimed_hash = data.get("manifest_sha256")
    # Verify hash against pure content
    copy_data = dict(data)
    copy_data.pop("manifest_sha256", None)
    import hashlib
    computed_hash = hashlib.sha256(json.dumps(copy_data, sort_keys=True).encode()).hexdigest()

    is_valid = (claimed_hash == computed_hash)
    return {
        "success": True,
        "data": {
            "report_id": report_id,
            "manifest_verified": is_valid,
            "claimed_sha256": claimed_hash,
            "computed_sha256": computed_hash,
        },
        "request_id": f"req_{uuid.uuid4().hex[:8]}",
    }
