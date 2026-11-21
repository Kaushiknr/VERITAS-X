"""Tests for Immutable Evidence Vault & Integrity Verification."""
import tempfile
from pathlib import Path
from vault.storage import EvidenceVault

def test_vault_storage_and_integrity():
    with tempfile.TemporaryDirectory() as tmpdir:
        vault = EvidenceVault(base_vault_path=Path(tmpdir))
        case_id = "test_case_001"
        evidence_id = "ev_001"
        filename = "usb_activity.json"
        content = b'{"event": "usb_connected", "device": "SanDisk-32GB"}'

        # Store evidence
        canonical_ev = vault.store_evidence(
            case_id=case_id,
            evidence_id=evidence_id,
            filename=filename,
            file_bytes=content,
            acquired_by="investigator_test",
            source_system="FORENSIC-PC",
        )

        assert canonical_ev.evidence_id == evidence_id
        assert canonical_ev.identity.size_bytes == len(content)
        assert canonical_ev.storage.read_only is True
        assert len(canonical_ev.acquisition.original_sha256) == 64

        # Verify integrity against baseline
        is_valid, current_hash = vault.verify_vault_file(
            case_id, evidence_id, filename, canonical_ev.acquisition.original_sha256
        )
        assert is_valid is True
        assert current_hash == canonical_ev.acquisition.original_sha256
