"""Case Management API Routes for VERITAS-X with Synthetic Demo Seeder."""
import uuid
import json
from pathlib import Path
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from core.models import Case, Claim
from core.case_store import case_store
from audit.ledger import audit_ledger
from vault.storage import vault
from parsers import parse_evidence_file
from indexing.engine import search_engine

router = APIRouter(prefix="/cases", tags=["cases"])

class CaseCreateRequest(BaseModel):
    title: str
    description: str = ""
    case_type: str = "insider_threat"
    timezone: str = "UTC"

class CaseUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    case_type: Optional[str] = None
    timezone: Optional[str] = None
    status: Optional[str] = None

@router.post("")
def create_case(req: CaseCreateRequest) -> Dict[str, Any]:
    case_id = f"case_{uuid.uuid4().hex[:8]}"
    case = Case(
        case_id=case_id,
        title=req.title,
        description=req.description,
        case_type=req.case_type,
        timezone=req.timezone,
        status="active",
    )
    created = case_store.create_case(case)
    audit_ledger.append_event(
        case_id=case_id,
        actor_id="investigator_local",
        action="case_created",
        target_id=case_id,
        details={"title": req.title, "type": req.case_type},
    )
    return {"success": True, "data": created.model_dump(), "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.get("")
def list_cases() -> Dict[str, Any]:
    cases = case_store.list_cases()
    return {"success": True, "data": [c.model_dump() for c in cases], "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.get("/{case_id}")
def get_case(case_id: str) -> Dict[str, Any]:
    case = case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail={"code": "CASE_NOT_FOUND", "message": f"Case {case_id} not found"})
    return {"success": True, "data": case.model_dump(), "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.patch("/{case_id}")
def update_case(case_id: str, req: CaseUpdateRequest) -> Dict[str, Any]:
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    updated = case_store.update_case(case_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail={"code": "CASE_NOT_FOUND", "message": f"Case {case_id} not found"})
    audit_ledger.append_event(
        case_id=case_id,
        actor_id="investigator_local",
        action="case_updated",
        target_id=case_id,
        details=updates,
    )
    return {"success": True, "data": updated.model_dump(), "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.post("/{case_id}/archive")
def archive_case(case_id: str) -> Dict[str, Any]:
    updated = case_store.update_case(case_id, {"status": "archived"})
    if not updated:
        raise HTTPException(status_code=404, detail={"code": "CASE_NOT_FOUND", "message": f"Case {case_id} not found"})
    audit_ledger.append_event(
        case_id=case_id,
        actor_id="investigator_local",
        action="case_archived",
        target_id=case_id,
    )
    return {"success": True, "data": updated.model_dump(), "request_id": f"req_{uuid.uuid4().hex[:8]}"}

@router.post("/seed/demo")
def seed_demo_case() -> Dict[str, Any]:
    """Generates a comprehensive USB Data Exfiltration forensic case with verified artifacts."""
    case_id = f"case_demo_{uuid.uuid4().hex[:6]}"
    case = Case(
        case_id=case_id,
        title="Operation Aegis: Suspected Trade Secret Exfiltration",
        description="Forensic investigation into unauthorized data transfer from FIN-WS-09 to removable storage before employee departure.",
        case_type="insider_threat",
        timezone="UTC",
        status="active",
    )
    case_store.create_case(case)
    audit_ledger.append_event(
        case_id=case_id,
        actor_id="investigator_lead",
        action="case_created",
        target_id=case_id,
        details={"title": case.title, "type": case.case_type},
    )

    # 1. USB Connection Evidence
    ev1_id = f"ev_usb_{uuid.uuid4().hex[:6]}"
    usb_data = [
        {
            "event_type": "usb_connection",
            "action": "device_mounted",
            "timestamp": "2026-11-21T08:14:22Z",
            "hostname": "FIN-WS-09",
            "username": "jsmith",
            "serial_number": "SANDISK-32GB-SN90214",
            "vendor": "SanDisk Extreme Pro",
            "device_id": "SANDISK-32GB-SN90214",
            "device_type": "usb",
        },
        {
            "event_type": "usb_activity",
            "action": "filesystem_mounted_drive_e",
            "timestamp": "2026-11-21T08:14:25Z",
            "hostname": "FIN-WS-09",
            "username": "jsmith",
            "device_id": "SANDISK-32GB-SN90214",
            "device_type": "usb",
        }
    ]
    usb_bytes = json.dumps(usb_data, indent=2).encode("utf-8")
    ev1 = vault.store_evidence(
        case_id=case_id,
        evidence_id=ev1_id,
        filename="usb_mounted_devices.json",
        file_bytes=usb_bytes,
        acquired_by="forensic_analyst",
        source_system="FIN-WS-09",
        file_type="application/json",
    )
    file_path1 = vault.get_vault_file_path(case_id, ev1_id, "usb_mounted_devices.json")
    ev1_events = parse_evidence_file(file_path1, "usb_mounted_devices.json", case_id, ev1_id, "run_01")
    search_engine.bulk_index_events(ev1_events)
    ev1.processing.status = "completed"
    ev1.processing.parser = "usb_history_parser"
    ev1.provenance.derived_record_count = len(ev1_events)
    case_store.register_evidence(ev1)
    search_engine.index_evidence_metadata(ev1)

    # 2. File Access Activity Evidence
    ev2_id = f"ev_access_{uuid.uuid4().hex[:6]}"
    access_data = [
        {
            "event_type": "file_access",
            "category": "file_activity",
            "action": "read",
            "timestamp": "2026-11-21T08:16:05Z",
            "username": "jsmith",
            "hostname": "FIN-WS-09",
            "filename": "q4_financial_projections.pdf",
            "filepath": "C:\\Users\\jsmith\\Confidential\\q4_financial_projections.pdf",
            "sha256": "7d9b9a622a59a35e4d257e0344d515a77038e21946eb2d0bc79df12720d207ec",
        },
        {
            "event_type": "file_access",
            "category": "file_activity",
            "action": "read",
            "timestamp": "2026-11-21T08:16:45Z",
            "username": "jsmith",
            "hostname": "FIN-WS-09",
            "filename": "client_acquisition_strategy.docx",
            "filepath": "C:\\Users\\jsmith\\Documents\\client_acquisition_strategy.docx",
        }
    ]
    access_bytes = json.dumps(access_data, indent=2).encode("utf-8")
    ev2 = vault.store_evidence(
        case_id=case_id,
        evidence_id=ev2_id,
        filename="security_audit_events.json",
        file_bytes=access_bytes,
        acquired_by="forensic_analyst",
        source_system="FIN-WS-09",
        file_type="application/json",
    )
    file_path2 = vault.get_vault_file_path(case_id, ev2_id, "security_audit_events.json")
    ev2_events = parse_evidence_file(file_path2, "security_audit_events.json", case_id, ev2_id, "run_02")
    search_engine.bulk_index_events(ev2_events)
    ev2.processing.status = "completed"
    ev2.processing.parser = "json_security_parser"
    ev2.provenance.derived_record_count = len(ev2_events)
    case_store.register_evidence(ev2)
    search_engine.index_evidence_metadata(ev2)

    # 3. Removable Media Write Evidence (CSV)
    ev3_id = f"ev_write_{uuid.uuid4().hex[:6]}"
    csv_data = (
        "timestamp,event_type,username,hostname,filename,filepath,device_type,device_identifier\n"
        "2026-11-21 08:17:10,removable_media_write,jsmith,FIN-WS-09,q4_financial_projections.pdf,E:\\q4_financial_projections.pdf,usb,SANDISK-32GB-SN90214\n"
        "2026-11-21 08:18:00,file_hash_observed,jsmith,FIN-WS-09,q4_financial_projections.pdf,E:\\q4_financial_projections.pdf,usb,SANDISK-32GB-SN90214\n"
    )
    ev3 = vault.store_evidence(
        case_id=case_id,
        evidence_id=ev3_id,
        filename="removable_media_writes.csv",
        file_bytes=csv_data.encode("utf-8"),
        acquired_by="forensic_analyst",
        source_system="FIN-WS-09",
        file_type="text/csv",
    )
    file_path3 = vault.get_vault_file_path(case_id, ev3_id, "removable_media_writes.csv")
    ev3_events = parse_evidence_file(file_path3, "removable_media_writes.csv", case_id, ev3_id, "run_03")
    search_engine.bulk_index_events(ev3_events)
    ev3.processing.status = "completed"
    ev3.processing.parser = "csv_forensic_parser"
    ev3.provenance.derived_record_count = len(ev3_events)
    case_store.register_evidence(ev3)
    search_engine.index_evidence_metadata(ev3)

    # 4. Seed Representative Claims
    clm1 = Claim(
        claim_id=f"claim_{uuid.uuid4().hex[:8]}",
        case_id=case_id,
        statement="User jsmith transferred q4_financial_projections.pdf to unauthorized USB device SANDISK-32GB-SN90214.",
        claim_type="usb_file_transfer",
        subject="jsmith",
        object="q4_financial_projections.pdf",
        target_device="SANDISK-32GB-SN90214",
    )
    case_store.create_claim(clm1)

    clm2 = Claim(
        claim_id=f"claim_{uuid.uuid4().hex[:8]}",
        case_id=case_id,
        statement="User admin copied database_backup.sql to external USB.",
        claim_type="usb_file_transfer",
        subject="admin",
        object="database_backup.sql",
    )
    case_store.create_claim(clm2)

    audit_ledger.append_event(
        case_id=case_id,
        actor_id="investigator_lead",
        action="demo_investigation_seeded",
        target_id=case_id,
        details={"case_id": case_id, "records_count": len(ev1_events) + len(ev2_events) + len(ev3_events)},
    )

    return {
        "success": True,
        "data": {
            "case": case.model_dump(),
            "evidence_count": 3,
            "events_count": len(ev1_events) + len(ev2_events) + len(ev3_events),
            "claims_count": 2,
        },
        "request_id": f"req_{uuid.uuid4().hex[:8]}",
    }
