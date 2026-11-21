"""Unit Tests for SHA-256 Hash-Chained Audit Ledger."""
import tempfile
import json
from pathlib import Path
from audit.ledger import AuditLedger

def test_audit_hash_chain_and_tamper_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger_file = Path(tmpdir) / "test_audit.jsonl"
        ledger = AuditLedger(ledger_file=ledger_file)

        # Append two valid transactions
        ev1 = ledger.append_event(
            case_id="case_001",
            actor_id="investigator_1",
            action="case_created",
            target_id="case_001",
            details={"title": "Test Case"},
        )
        ev2 = ledger.append_event(
            case_id="case_001",
            actor_id="investigator_1",
            action="evidence_acquired",
            target_id="ev_001",
            details={"sha256": "abc"},
        )

        assert ev2.previous_record_hash == ev1.record_hash

        # Verify integrity
        is_valid, err, count = ledger.verify_ledger_integrity()
        assert is_valid is True
        assert count == 2
        assert err is None

        # Simulate tampering by editing the first record
        with open(ledger_file, "r") as f:
            lines = f.readlines()
        rec1 = json.loads(lines[0])
        rec1["details"]["title"] = "Tampered Title"
        lines[0] = json.dumps(rec1) + "\n"
        with open(ledger_file, "w") as f:
            f.writelines(lines)

        # Integrity verification must catch tampering
        is_valid, err, count = ledger.verify_ledger_integrity()
        assert is_valid is False
        assert "Tampered record" in str(err)
