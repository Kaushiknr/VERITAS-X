"""Automated Tests using Real-World Forensic Datasets."""
import os
import uuid
from pathlib import Path
import pytest
from core.models import Claim, Case
from core.case_store import case_store
from vault.storage import vault
from parsers.linux_auth_parser import LinuxAuthParser
from parsers.sysmon_parser import SysmonWindowsParser
from parsers import parse_evidence_file
from indexing.engine import search_engine
from playbooks.schema import playbook_loader
from engine.ega import ega_engine
from engine.cav import cav_engine
from reporting.report_generator import report_generator
from audit.ledger import audit_ledger

BASE_DIR = Path(__file__).resolve().parent.parent
DATASETS_DIR = BASE_DIR / "data" / "real_datasets"

def test_real_openssh_log_parsing():
    """Verify parsing real OpenSSH authentication logs from production servers."""
    log_path = DATASETS_DIR / "real_openssh_auth.log"
    assert log_path.exists(), "real_openssh_auth.log dataset must exist"

    parser = LinuxAuthParser()
    events = parser.parse(log_path, "case_real_01", "ev_ssh_real", "run_real_01")
    
    assert len(events) > 50, f"Expected >50 events from real SSH log, got {len(events)}"
    
    # Check that real brute-force attempts with usernames and IPs were extracted
    users = [e.actor.username for e in events if e.actor.username]
    ips = [e.network.source_ip for e in events if e.network.source_ip]
    assert len(users) > 0, "Should extract real usernames"
    assert len(ips) > 0, "Should extract real attacker source IPs"
    assert any(e.event.action == "invalid_user_probe" for e in events)

def test_real_attack_sysmon_evtx_parsing():
    """Verify parsing real attack binary EVTX logs with Sysmon process & file creation events."""
    evtx_path = DATASETS_DIR / "real_attack_sysmon_execution.evtx"
    assert evtx_path.exists(), "real_attack_sysmon_execution.evtx dataset must exist"

    parser = SysmonWindowsParser()
    events = parser.parse(evtx_path, "case_real_02", "ev_evtx_real", "run_real_02")

    assert len(events) == 11, f"Expected 11 real Sysmon events, got {len(events)}"
    
    # Verify real process execution records
    proc_events = [e for e in events if e.event.type == "process_creation"]
    assert len(proc_events) > 0
    proc_names = [e.process.name for e in proc_events if e.process.name]
    assert any("rundll32.exe" in p for p in proc_names)
    assert any("calc.exe" in p for p in proc_names)

def test_real_dataset_end_to_end_investigation():
    """Verify full forensic investigation lifecycle using real attack datasets."""
    case_id = f"case_real_{uuid.uuid4().hex[:6]}"
    ev_id = f"ev_real_{uuid.uuid4().hex[:6]}"
    evtx_path = DATASETS_DIR / "real_attack_sysmon_execution.evtx"

    with open(evtx_path, "rb") as f:
        file_bytes = f.read()

    # 1. Store in immutable vault & verify bit-level integrity
    canonical_ev = vault.store_evidence(
        case_id=case_id,
        evidence_id=ev_id,
        filename="real_attack_sysmon.evtx",
        file_bytes=file_bytes,
        acquired_by="dfir_investigator",
        source_system="ATTACK-TARGET-VM",
    )
    assert canonical_ev.integrity.status == "verified"
    assert len(canonical_ev.acquisition.original_sha256) == 64

    # 2. Parse into normalized events
    stored_path = vault.get_vault_file_path(case_id, ev_id, "real_attack_sysmon.evtx")
    events = parse_evidence_file(stored_path, "real_attack_sysmon.evtx", case_id, ev_id, "run_real_e2e")
    assert len(events) == 11

    # 3. Bulk Index into Search Engine
    search_engine.bulk_index_events(events)

    # 4. Run Evidence Gap Analysis against Ransomware/Malware Playbook
    playbook = playbook_loader.get_playbook("ransomware_activity")
    assert playbook is not None
    ega_res = ega_engine.evaluate_coverage(case_id, playbook, events, [canonical_ev])
    
    # Suspicious process requirement must be observed due to rundll32.exe execution
    eval_map = {r.requirement_id: r.status for r in ega_res.evaluations}
    assert eval_map["suspicious_process"] == "observed"
    assert ega_res.coverage_score > 0

    # 5. Run Claim-Aware Verification (CAV)
    claim = Claim(
        claim_id="clm_real_attack_01",
        case_id=case_id,
        statement="Suspicious process rundll32 executed on target system.",
        claim_type="automated_encryption",
    )
    assessment = cav_engine.verify_claim(claim, playbook, events)
    assert len(assessment.supporting_evidence) > 0
    assert assessment.requires_human_review is True

    # 6. Generate Verifiable Report Package
    chain_valid, _, count = audit_ledger.verify_ledger_integrity()
    test_case = case_store.get_case(case_id)
    if not test_case:
        test_case = case_store.create_case(Case(case_id=case_id, title="Real Attack Investigation", description="Testing with real EVTX logs"))
    report_pkg = report_generator.generate_report(
        case=test_case,
        evidence_list=[canonical_ev],
        ega_result=ega_res,
        assessments=[assessment],
        audit_chain_valid=chain_valid,
        audit_record_count=count,
    )
    assert len(report_pkg["manifest_sha256"]) == 64
    assert Path(report_pkg["html_path"]).exists()
