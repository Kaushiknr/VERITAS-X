"""Immutable Evidence Vault and Integrity Verification Service for VERITAS-X."""
import hashlib
import os
import stat
import shutil
from pathlib import Path
from typing import Tuple, Optional
from core.config import settings
from core.models import (
    CanonicalEvidence,
    EvidenceIdentity,
    EvidenceAcquisition,
    EvidenceStorage,
    EvidenceIntegrity,
    EvidenceProcessing,
    EvidenceProvenance,
    generate_utc_timestamp,
)

class EvidenceVault:
    """Manages bit-level evidence preservation, hashing, and read-only isolation."""

    def __init__(self, base_vault_path: Optional[Path] = None):
        self.base_path = base_vault_path or settings.vault_path
        self.base_path.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def calculate_sha256(file_path: Path) -> str:
        """Calculate SHA-256 of a file using buffered streaming."""
        sha = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        return sha.hexdigest().lower()

    @staticmethod
    def calculate_bytes_sha256(data: bytes) -> str:
        """Calculate SHA-256 from in-memory byte buffer."""
        return hashlib.sha256(data).hexdigest().lower()

    def store_evidence(
        self,
        case_id: str,
        evidence_id: str,
        filename: str,
        file_bytes: bytes,
        acquired_by: str,
        source_system: str,
        file_type: str = "application/octet-stream",
        acquisition_method: str = "authorized_export",
    ) -> CanonicalEvidence:
        """Store original evidence into immutable vault, compute hash and verify."""
        case_dir = self.base_path / case_id / evidence_id
        case_dir.mkdir(parents=True, exist_ok=True)

        destination_path = case_dir / filename
        if destination_path.exists():
            raise FileExistsError(f"Evidence file {filename} already exists in vault for {evidence_id}")

        # Compute pre-write acquisition hash
        acquisition_sha256 = self.calculate_bytes_sha256(file_bytes)
        size_bytes = len(file_bytes)

        # Write to vault
        with open(destination_path, "wb") as f:
            f.write(file_bytes)

        # Make file read-only to prevent tampering
        os.chmod(destination_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

        # Post-write bit-level verification
        stored_sha256 = self.calculate_sha256(destination_path)
        if stored_sha256 != acquisition_sha256:
            raise IOError("Bit corruption detected during vault write! Hashes do not match.")

        now_utc = generate_utc_timestamp()
        rel_object_id = f"vault/{case_id}/{evidence_id}/{filename}"

        return CanonicalEvidence(
            evidence_id=evidence_id,
            case_id=case_id,
            identity=EvidenceIdentity(
                original_filename=filename,
                file_type=file_type,
                size_bytes=size_bytes,
            ),
            acquisition=EvidenceAcquisition(
                acquired_at=now_utc,
                acquired_by=acquired_by,
                source_system=source_system,
                acquisition_method=acquisition_method,
                original_sha256=acquisition_sha256,
            ),
            storage=EvidenceStorage(
                object_id=rel_object_id,
                stored_sha256=stored_sha256,
                storage_version="1",
                read_only=True,
            ),
            processing=EvidenceProcessing(
                status="pending",
                parser="unassigned",
                parser_version="1.0.0",
            ),
            integrity=EvidenceIntegrity(
                status="verified",
                verification_method="sha256",
                verified_at=now_utc,
                baseline_reference=f"acquisition_hash_{acquisition_sha256[:12]}",
            ),
            provenance=EvidenceProvenance(
                source_record_count=0,
                derived_record_count=0,
                chain_of_custody_id=f"coc_{evidence_id}",
            ),
        )

    def verify_vault_file(self, case_id: str, evidence_id: str, filename: str, expected_sha256: str) -> Tuple[bool, str]:
        """Verify that an existing vault item matches its expected baseline hash."""
        target_path = self.base_path / case_id / evidence_id / filename
        if not target_path.exists():
            return False, f"File {target_path} not found in vault"
        
        current_hash = self.calculate_sha256(target_path)
        is_valid = (current_hash == expected_sha256.lower())
        return is_valid, current_hash

    def get_vault_file_path(self, case_id: str, evidence_id: str, filename: str) -> Path:
        """Resolve read-only file path for parsing."""
        target_path = self.base_path / case_id / evidence_id / filename
        if not target_path.exists():
            raise FileNotFoundError(f"Vault evidence file {target_path} not found")
        return target_path

vault = EvidenceVault()
