"""Append-only SHA-256 Hash-Chained Audit Ledger for VERITAS-X."""
import hashlib
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from core.config import settings
from core.models import AuditEvent, generate_utc_timestamp

GENESIS_PREVIOUS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

def canonical_json(data: Dict[str, Any]) -> str:
    """Serialize dictionary deterministically with sorted keys and compact separators."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))

class AuditLedger:
    """Cryptographically chained append-only audit trail."""

    def __init__(self, ledger_file: Optional[Path] = None):
        self.ledger_file = ledger_file or (settings.vault_path.parent / "db" / "audit_ledger.jsonl")
        self.ledger_file.parent.mkdir(parents=True, exist_ok=True)
        self._init_ledger()

    def _init_ledger(self) -> None:
        if not self.ledger_file.exists():
            self.ledger_file.touch()

    def get_last_hash(self, case_id: Optional[str] = None) -> str:
        """Find the hash of the last entry in the ledger."""
        last_hash = GENESIS_PREVIOUS_HASH
        if not self.ledger_file.exists():
            return last_hash

        with open(self.ledger_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if case_id is None or record.get("case_id") == case_id:
                    last_hash = record.get("record_hash", last_hash)
        return last_hash

    def append_event(
        self,
        case_id: str,
        actor_id: str,
        action: str,
        target_id: str,
        result: str = "success",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Append an event to the ledger with SHA-256 hash chaining."""
        prev_hash = self.get_last_hash()
        timestamp = generate_utc_timestamp()
        audit_id = f"audit_{hashlib.sha256(f'{case_id}:{action}:{timestamp}'.encode()).hexdigest()[:16]}"
        details = details or {}

        # Construct canonical payload for hashing
        payload = {
            "audit_id": audit_id,
            "case_id": case_id,
            "actor_id": actor_id,
            "action": action,
            "target_id": target_id,
            "timestamp_utc": timestamp,
            "result": result,
            "previous_record_hash": prev_hash,
            "details": details,
        }
        canonical_str = canonical_json(payload)
        record_hash = hashlib.sha256(f"{prev_hash}{canonical_str}".encode()).hexdigest()

        event = AuditEvent(
            audit_id=audit_id,
            case_id=case_id,
            actor_id=actor_id,
            action=action,
            target_id=target_id,
            timestamp_utc=timestamp,
            result=result,
            previous_record_hash=prev_hash,
            record_hash=record_hash,
            details=details,
        )

        with open(self.ledger_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event.model_dump()) + "\n")

        return event

    def verify_ledger_integrity(self) -> Tuple[bool, Optional[str], int]:
        """Verify the cryptographic hash chain of the entire ledger."""
        if not self.ledger_file.exists():
            return True, None, 0

        expected_prev_hash = GENESIS_PREVIOUS_HASH
        count = 0

        with open(self.ledger_file, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                actual_prev_hash = record.get("previous_record_hash")
                actual_record_hash = record.get("record_hash")

                if actual_prev_hash != expected_prev_hash:
                    return (
                        False,
                        f"Chain broken at record #{line_no} ({record.get('audit_id')}): "
                        f"Expected prev_hash {expected_prev_hash}, found {actual_prev_hash}",
                        count,
                    )

                # Re-compute hash
                payload = {
                    "audit_id": record["audit_id"],
                    "case_id": record["case_id"],
                    "actor_id": record["actor_id"],
                    "action": record["action"],
                    "target_id": record["target_id"],
                    "timestamp_utc": record["timestamp_utc"],
                    "result": record["result"],
                    "previous_record_hash": actual_prev_hash,
                    "details": record.get("details", {}),
                }
                computed_hash = hashlib.sha256(f"{actual_prev_hash}{canonical_json(payload)}".encode()).hexdigest()

                if computed_hash != actual_record_hash:
                    return (
                        False,
                        f"Tampered record at #{line_no} ({record.get('audit_id')}): "
                        f"Computed hash {computed_hash} != stored hash {actual_record_hash}",
                        count,
                    )

                expected_prev_hash = actual_record_hash
                count += 1

        return True, None, count

    def get_events(self, case_id: Optional[str] = None, limit: int = 100) -> List[AuditEvent]:
        """Retrieve audit entries with optional case filtering."""
        events: List[AuditEvent] = []
        if not self.ledger_file.exists():
            return events

        with open(self.ledger_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if case_id is None or record.get("case_id") == case_id:
                    events.append(AuditEvent(**record))

        return events[-limit:]

from typing import Tuple
audit_ledger = AuditLedger()
