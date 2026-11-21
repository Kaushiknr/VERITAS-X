"""Unit Tests for Evidence Gap Analysis (EGA) Engine."""
from engine.ega import EvidenceGapAnalysisEngine
from playbooks.schema import playbook_loader
from core.models import NormalizedEvent, EventAction, EventTime, EventActor, EventHost, EventFile, EventDevice, EventProcess, EventNetwork, EventSource, EventProvenance, CanonicalEvidence, EvidenceIdentity, EvidenceAcquisition, EvidenceStorage, EvidenceIntegrity

def test_ega_coverage_calculation():
    ega = EvidenceGapAnalysisEngine()
    playbook = playbook_loader.get_playbook("usb_data_exfiltration")
    assert playbook is not None

    # Construct mock USB connection event
    usb_event = NormalizedEvent(
        event_id="evt_01",
        schema_version="1.0.0",
        case_id="case_001",
        evidence_id="ev_001",
        event=EventAction(type="usb_connection", category="hardware", action="connection"),
        time=EventTime(original="2026-11-21T09:00:00Z", timestamp_utc="2026-11-21T09:00:00Z", precision="second"),
        actor=EventActor(username="jsmith"),
        host=EventHost(hostname="LAB-PC-01"),
        file=EventFile(),
        device=EventDevice(type="usb", identifier="USB-SANDISK-01"),
        process=EventProcess(),
        network=EventNetwork(),
        source=EventSource(format="json", parser="json_parser", record_locator="1"),
        provenance=EventProvenance(extraction_run_id="run_1"),
    )

    result = ega.evaluate_coverage(
        case_id="case_001",
        playbook=playbook,
        events=[usb_event],
        collected_evidence=[],
    )

    # usb_connection requirement should be observed (contrib 1.0)
    eval_map = {r.requirement_id: r.status for r in result.evaluations}
    assert eval_map["usb_connection"] == "observed"
    # Other requirements should be not_found or not_collected
    assert eval_map["removable_media_write"] in ("not_found", "not_collected")
    # Coverage score should be greater than 0 but less than 100
    assert 0 < result.coverage_score < 100
    # Recommendations should be triggered for missing items
    assert len(result.recommendations) > 0
