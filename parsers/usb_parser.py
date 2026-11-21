"""USB Forensic Artifact Parser for VERITAS-X."""
import csv
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from parsers.base import BaseParser
from core.models import NormalizedEvent
from normalization.normalizer import normalizer

class USBHistoryParser(BaseParser):
    name: str = "usb_history_parser"
    version: str = "1.0.0"
    supported_formats: List[str] = ["usb_csv", "usb_json", "setupapi_log"]

    def can_parse(self, file_path: Path, filename: str) -> bool:
        lower = filename.lower()
        return "usb" in lower or "setupapi" in lower or "mounted" in lower

    def parse(
        self,
        file_path: Path,
        case_id: str,
        evidence_id: str,
        extraction_run_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        options = options or {}
        assumed_tz = options.get("timezone", "UTC")
        ext = file_path.suffix.lower()

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()

        if ext == ".json" or content.startswith("{") or content.startswith("["):
            try:
                data = json.loads(content)
                records = data if isinstance(data, list) else data.get("usb_devices", [data])
                for idx, r in enumerate(records, start=1):
                    raw_time = r.get("connected_at") or r.get("timestamp") or r.get("time")
                    dev_id = r.get("serial_number") or r.get("device_identifier") or r.get("identifier") or r.get("device_id")
                    vendor = r.get("vendor") or r.get("device_name") or "USB Storage"
                    action = r.get("action") or "connection"
                    ev_type = "usb_connection" if "connect" in action.lower() else "usb_activity"

                    evt = normalizer.build_normalized_event(
                        event_id=f"evt_usb_{evidence_id}_{idx}",
                        case_id=case_id,
                        evidence_id=evidence_id,
                        event_type=ev_type,
                        category="hardware",
                        action=action,
                        raw_timestamp=raw_time,
                        source_format="usb_json",
                        parser_name=self.name,
                        parser_version=self.version,
                        record_locator=f"usb_entry:{idx}",
                        extraction_run_id=extraction_run_id,
                        outcome="success",
                        assumed_tz=assumed_tz,
                        hostname=r.get("hostname"),
                        username=r.get("username"),
                        device_type="usb",
                        device_identifier=dev_id,
                        file_name=r.get("volume_name") or vendor,
                    )
                    events.append(evt)
                return events
            except Exception:
                pass

        # CSV format (e.g. USBDeview exports or registry MountedDevices CSV)
        try:
            reader = csv.DictReader(content.splitlines())
            for idx, row in enumerate(reader, start=1):
                clean = {k.strip().lower(): v.strip() for k, v in row.items() if k}
                raw_time = (
                    clean.get("connect time")
                    or clean.get("connected_at")
                    or clean.get("timestamp")
                    or clean.get("event time")
                )
                dev_id = clean.get("serial number") or clean.get("serial") or clean.get("device_id")
                vendor = clean.get("device name") or clean.get("description") or clean.get("vendor") or "USB Device"
                action = clean.get("action") or "connection"
                ev_type = "usb_connection" if "disconnect" not in action.lower() else "usb_disconnection"

                evt = normalizer.build_normalized_event(
                    event_id=f"evt_usb_csv_{evidence_id}_{idx}",
                    case_id=case_id,
                    evidence_id=evidence_id,
                    event_type=ev_type,
                    category="hardware",
                    action=action,
                    raw_timestamp=raw_time,
                    source_format="usb_csv",
                    parser_name=self.name,
                    parser_version=self.version,
                    record_locator=f"usb_csv_row:{idx}",
                    extraction_run_id=extraction_run_id,
                    outcome="success",
                    assumed_tz=assumed_tz,
                    hostname=clean.get("computer") or clean.get("host"),
                    username=clean.get("user") or clean.get("username"),
                    device_type="usb",
                    device_identifier=dev_id,
                    file_name=vendor,
                )
                events.append(evt)
        except Exception:
            pass

        return events
