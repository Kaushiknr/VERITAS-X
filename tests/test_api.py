"""Integration Tests for FastAPI Endpoints."""
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

def test_health_check():
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["data"]["status"] == "healthy"

def test_case_lifecycle():
    # 1. Create Case
    create_payload = {
        "title": "USB Exfiltration Test Case",
        "description": "Integration test investigation",
        "case_type": "insider_threat",
        "timezone": "UTC",
    }
    res = client.post("/api/v1/cases", json=create_payload)
    assert res.status_code == 200
    case_data = res.json()["data"]
    case_id = case_data["case_id"]

    # 2. Get Case
    res = client.get(f"/api/v1/cases/{case_id}")
    assert res.status_code == 200
    assert res.json()["data"]["title"] == "USB Exfiltration Test Case"

    # 3. List Playbooks
    res = client.get("/api/v1/playbooks")
    assert res.status_code == 200
    playbooks = res.json()["data"]
    assert len(playbooks) >= 1
    assert any(p["id"] == "usb_data_exfiltration" for p in playbooks)

    # 4. Upload Evidence File
    test_json_content = b'[{"event_type": "usb_connection", "action": "connection", "timestamp": "2026-11-21T09:00:00Z", "hostname": "PC-01", "device_id": "USB-TEST-01"}]'
    files = {"file": ("test_usb.json", test_json_content, "application/json")}
    res = client.post(f"/api/v1/cases/{case_id}/evidence", files=files)
    assert res.status_code == 200
    ev_data = res.json()["data"]
    evidence_id = ev_data["evidence"]["evidence_id"]
    assert ev_data["indexed_events_count"] == 1

    # 5. Verify Evidence
    res = client.post(f"/api/v1/evidence/{evidence_id}/verify")
    assert res.status_code == 200
    assert res.json()["data"]["integrity_verified"] is True

    # 6. Check Timeline
    res = client.get(f"/api/v1/investigations/{case_id}/timeline")
    assert res.status_code == 200
    events = res.json()["data"]["events"]
    assert len(events) == 1

    # 7. Check Coverage (EGA)
    res = client.get(f"/api/v1/investigations/{case_id}/coverage?playbook_id=usb_data_exfiltration")
    assert res.status_code == 200
    cov_data = res.json()["data"]
    assert cov_data["coverage_score"] > 0

    # 8. Register & Verify Claim (CAV)
    claim_payload = {
        "statement": "Target device USB-TEST-01 was attached.",
        "claim_type": "usb_file_transfer",
        "target_device": "USB-TEST-01",
    }
    res = client.post(f"/api/v1/cases/{case_id}/claims", json=claim_payload)
    assert res.status_code == 200
    claim_id = res.json()["data"]["claim_id"]

    res = client.post(f"/api/v1/claims/{claim_id}/verify", json={"playbook_id": "usb_data_exfiltration"})
    assert res.status_code == 200
    ass_data = res.json()["data"]
    assert ass_data["status"] in ("supported", "partially_supported")

    # 9. Generate Report
    res = client.post(f"/api/v1/cases/{case_id}/reports", json={"playbook_id": "usb_data_exfiltration"})
    assert res.status_code == 200
    rep_pkg = res.json()["data"]
    assert "report_id" in rep_pkg
    assert len(rep_pkg["manifest_sha256"]) == 64

    # 10. Audit Ledger Verification
    res = client.post("/api/v1/audit/verify")
    assert res.status_code == 200
    assert res.json()["data"]["chain_valid"] is True
