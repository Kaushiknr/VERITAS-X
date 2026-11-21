"""Unit Tests for Claim-Aware Verification (CAV) Engine."""
from engine.cav import ClaimVerificationEngine
from playbooks.schema import playbook_loader
from core.models import Claim, NormalizedEvent, EventAction, EventTime, EventActor, EventHost, EventFile, EventDevice, EventProcess, EventNetwork, EventSource, EventProvenance

def test_cav_insufficient_evidence():
    cav = ClaimVerificationEngine()
    playbook = playbook_loader.get_playbook("usb_data_exfiltration")
    assert playbook is not None

    claim = Claim(
        claim_id="clm_01",
        case_id="case_001",
        statement="User transferred secret.pdf to USB drive.",
        claim_type="usb_file_transfer",
        subject="jsmith",
        object="secret.pdf",
    )

    # Empty events
    assessment = cav.verify_claim(claim, playbook, events=[])
    assert assessment.status == "insufficient_evidence"
    assert len(assessment.supporting_evidence) == 0
    assert assessment.requires_human_review is True

def test_cav_partial_support():
    cav = ClaimVerificationEngine()
    playbook = playbook_loader.get_playbook("usb_data_exfiltration")

    claim = Claim(
        claim_id="clm_02",
        case_id="case_001",
        statement="User transferred secret.pdf to USB drive.",
        claim_type="usb_file_transfer",
        subject="jsmith",
        object="secret.pdf",
        target_device="USB-DEVICE-99",
    )

    # We only have USB connection event, but not removable media write or file access
    usb_event = NormalizedEvent(
        event_id="evt_usb_1",
        schema_version="1.0.0",
        case_id="case_001",
        evidence_id="ev_001",
        event=EventAction(type="usb_connection", category="hardware", action="connection"),
        time=EventTime(original="2026-11-21T09:00:00Z", timestamp_utc="2026-11-21T09:00:00Z", precision="second"),
        actor=EventActor(username="jsmith"),
        host=EventHost(hostname="LAB-PC-01"),
        file=EventFile(),
        device=EventDevice(type="usb", identifier="USB-DEVICE-99"),
        process=EventProcess(),
        network=EventNetwork(),
        source=EventSource(format="json", parser="json_parser", record_locator="1"),
        provenance=EventProvenance(extraction_run_id="run_1"),
    )

    assessment = cav.verify_claim(claim, playbook, events=[usb_event])
    assert assessment.status == "partially_supported"
    assert "evt_usb_1" in assessment.supporting_evidence
    assert "removable_media_write" in assessment.unresolved_requirements
