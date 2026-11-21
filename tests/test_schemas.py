"""Unit Tests for Canonical Evidence and Event Schemas."""
import pytest
from pydantic import ValidationError
from core.models import (
    CanonicalEvidence,
    EvidenceIdentity,
    EvidenceAcquisition,
    EvidenceStorage,
    EvidenceIntegrity,
    NormalizedEvent,
)
from normalization.normalizer import normalizer

def test_evidence_sha256_validation():
    valid_sha = "a" * 64
    invalid_sha = "not_a_valid_sha256"

    # Should succeed with valid 64-char hex
    acq = EvidenceAcquisition(
        acquired_at="2026-11-21T08:00:00Z",
        acquired_by="investigator_001",
        source_system="HOST-01",
        original_sha256=valid_sha,
    )
    assert acq.original_sha256 == valid_sha

    # Should raise error with invalid sha
    with pytest.raises(ValidationError):
        EvidenceAcquisition(
            acquired_at="2026-11-21T08:00:00Z",
            acquired_by="investigator_001",
            source_system="HOST-01",
            original_sha256=invalid_sha,
        )

def test_timestamp_normalization():
    # ISO8601 with Z
    ts_utc, orig, tz = normalizer.normalize_timestamp("2026-11-21T08:30:00Z")
    assert "2026-11-21T08:30:00" in ts_utc
    assert tz == "UTC"

    # Unix epoch seconds
    ts_utc, orig, tz = normalizer.normalize_timestamp("1700000000")
    assert "2023-" in ts_utc

    # Standard format string
    ts_utc, orig, tz = normalizer.normalize_timestamp("2026-11-21 14:00:00")
    assert "2026-11-21T14:00:00" in ts_utc
