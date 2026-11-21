"""Canonical domain models and schemas for VERITAS-X."""
from __future__ import annotations
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator
import re
from datetime import datetime, timezone

def generate_utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()

class EvidenceIdentity(BaseModel):
    original_filename: str
    file_type: str
    size_bytes: int

class EvidenceAcquisition(BaseModel):
    acquired_at: str
    acquired_by: str
    source_system: str
    acquisition_method: str = "authorized_export"
    original_sha256: str

    @field_validator("original_sha256")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        v = v.strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", v):
            raise ValueError("SHA-256 must be a 64-character lowercase hex string")
        return v

class EvidenceStorage(BaseModel):
    object_id: str
    stored_sha256: str
    storage_version: str = "1"
    read_only: bool = True

    @field_validator("stored_sha256")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        v = v.strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", v):
            raise ValueError("SHA-256 must be a 64-character lowercase hex string")
        return v

class EvidenceProcessing(BaseModel):
    status: str = "pending"  # pending, completed, failed
    parser: str = "unknown"
    parser_version: str = "1.0.0"
    processing_run_id: str = ""
    processed_at: Optional[str] = None
    error_message: Optional[str] = None

class EvidenceIntegrity(BaseModel):
    status: str = "verified"  # verified, mismatch, unverified
    verification_method: str = "sha256"
    verified_at: str
    baseline_reference: str

class EvidenceProvenance(BaseModel):
    source_record_count: int = 0
    derived_record_count: int = 0
    chain_of_custody_id: str = ""

class CanonicalEvidence(BaseModel):
    schema_version: str = "1.0.0"
    evidence_id: str
    case_id: str
    identity: EvidenceIdentity
    acquisition: EvidenceAcquisition
    storage: EvidenceStorage
    processing: EvidenceProcessing = Field(default_factory=EvidenceProcessing)
    integrity: EvidenceIntegrity
    provenance: EvidenceProvenance = Field(default_factory=EvidenceProvenance)

# Normalized Event Models
class EventAction(BaseModel):
    type: str
    category: str
    action: str
    outcome: str = "unknown"

class EventTime(BaseModel):
    original: str
    timezone: Optional[str] = "UTC"
    timestamp_utc: str
    precision: str = "second"

class EventActor(BaseModel):
    user_id: Optional[str] = None
    username: Optional[str] = None

class EventHost(BaseModel):
    hostname: Optional[str] = None
    device_id: Optional[str] = None

class EventFile(BaseModel):
    name: Optional[str] = None
    path: Optional[str] = None
    sha256: Optional[str] = None

class EventDevice(BaseModel):
    type: Optional[str] = None
    identifier: Optional[str] = None

class EventProcess(BaseModel):
    name: Optional[str] = None
    pid: Optional[int] = None
    parent_pid: Optional[int] = None

class EventNetwork(BaseModel):
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None

class EventSource(BaseModel):
    format: str
    parser: str
    parser_version: str = "1.0.0"
    record_locator: str

class EventProvenance(BaseModel):
    extraction_run_id: str
    normalization_version: str = "1.0.0"

class NormalizedEvent(BaseModel):
    event_id: str
    schema_version: str = "1.0.0"
    case_id: str
    evidence_id: str
    event: EventAction
    time: EventTime
    actor: EventActor = Field(default_factory=EventActor)
    host: EventHost = Field(default_factory=EventHost)
    file: EventFile = Field(default_factory=EventFile)
    device: EventDevice = Field(default_factory=EventDevice)
    process: EventProcess = Field(default_factory=EventProcess)
    network: EventNetwork = Field(default_factory=EventNetwork)
    source: EventSource
    provenance: EventProvenance

# Case Model
class Case(BaseModel):
    case_id: str
    title: str
    description: str
    case_type: str = "digital_forensics"
    timezone: str = "UTC"
    status: str = "active"  # active, archived, closed
    created_at: str = Field(default_factory=generate_utc_timestamp)
    updated_at: str = Field(default_factory=generate_utc_timestamp)

# Audit Model
class AuditEvent(BaseModel):
    audit_id: str
    case_id: str
    actor_id: str
    action: str
    target_id: str
    timestamp_utc: str = Field(default_factory=generate_utc_timestamp)
    result: str = "success"  # success, failure
    previous_record_hash: str = "GENESIS_BLOCK"
    record_hash: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)

# Claim & Assessment Models
class Claim(BaseModel):
    claim_id: str
    case_id: str
    statement: str
    claim_type: str
    subject: Optional[str] = None
    object: Optional[str] = None
    target_device: Optional[str] = None
    created_at: str = Field(default_factory=generate_utc_timestamp)

class ClaimAssessment(BaseModel):
    claim_id: str
    assessment_id: str
    status: str  # supported, partially_supported, insufficient_evidence, contradicted, conflicting, unverified
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    unresolved_requirements: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    verification_rule_version: str = "1.0.0"
    requires_human_review: bool = True
    assessed_at: str = Field(default_factory=generate_utc_timestamp)
