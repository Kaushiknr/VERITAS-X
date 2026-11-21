"""JSON Forensic Log Parser for VERITAS-X."""
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from parsers.base import BaseParser
from core.models import NormalizedEvent
from normalization.normalizer import normalizer

class JSONSecurityParser(BaseParser):
    name: str = "json_security_parser"
    version: str = "1.0.0"
    supported_formats: List[str] = ["json", "jsonl"]

    def can_parse(self, file_path: Path, filename: str) -> bool:
        ext = filename.lower().split(".")[-1]
        return ext in self.supported_formats

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

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()

        # Try parsing as whole JSON array or object
        raw_records = []
        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                raw_records = parsed
            elif isinstance(parsed, dict):
                # Check if it has a list under 'events' or 'logs'
                for k in ["events", "logs", "records"]:
                    if isinstance(parsed.get(k), list):
                        raw_records = parsed[k]
                        break
                if not raw_records:
                    raw_records = [parsed]
        except json.JSONDecodeError:
            # Try line-delimited JSON
            for line_no, line in enumerate(content.splitlines(), start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw_records.append((line_no, json.loads(line)))
                except json.JSONDecodeError:
                    continue

        for idx, item in enumerate(raw_records):
            locator = f"record:{idx+1}"
            record = item
            if isinstance(item, tuple):
                locator = f"line:{item[0]}"
                record = item[1]

            if not isinstance(record, dict):
                continue

            # Extract fields with sensible fallbacks
            ev_type = record.get("event_type") or record.get("type") or record.get("action") or "generic_event"
            category = record.get("category") or "system"
            action = record.get("action") or ev_type
            raw_time = (
                record.get("timestamp")
                or record.get("time")
                or record.get("@timestamp")
                or record.get("datetime")
                or record.get("created_at")
            )
            outcome = record.get("outcome") or record.get("status") or "unknown"

            # Actor
            actor_dict = record.get("actor") if isinstance(record.get("actor"), dict) else {}
            username = (
                record.get("username")
                or record.get("user")
                or actor_dict.get("username")
                or record.get("user_name")
            )
            user_id = record.get("user_id") or actor_dict.get("user_id")

            # Host
            host_dict = record.get("host") if isinstance(record.get("host"), dict) else {}
            hostname = (
                record.get("hostname")
                or record.get("host")
                or host_dict.get("hostname")
                or record.get("computer_name")
            )
            if isinstance(hostname, dict):
                hostname = hostname.get("hostname")
            device_id = record.get("device_id") or host_dict.get("device_id")

            # File
            file_dict = record.get("file") if isinstance(record.get("file"), dict) else {}
            file_name = record.get("filename") or record.get("file_name") or file_dict.get("name")
            file_path_val = record.get("filepath") or record.get("file_path") or file_dict.get("path")
            file_sha256 = record.get("sha256") or record.get("file_hash") or file_dict.get("sha256")

            # Device
            dev_dict = record.get("device") if isinstance(record.get("device"), dict) else {}
            dev_type = record.get("device_type") or dev_dict.get("type")
            dev_id = (
                record.get("device_identifier")
                or record.get("target_device")
                or record.get("device_id")
                or dev_dict.get("identifier")
            )

            # Process
            proc_dict = record.get("process") if isinstance(record.get("process"), dict) else {}
            proc_name = record.get("process_name") or record.get("image") or proc_dict.get("name")
            pid = record.get("pid") or proc_dict.get("pid")
            parent_pid = record.get("parent_pid") or proc_dict.get("parent_pid")

            # Network
            net_dict = record.get("network") if isinstance(record.get("network"), dict) else {}
            src_ip = record.get("source_ip") or record.get("src_ip") or net_dict.get("source_ip")
            dst_ip = record.get("destination_ip") or record.get("dst_ip") or net_dict.get("destination_ip")
            dst_port = record.get("destination_port") or record.get("dst_port") or net_dict.get("destination_port")

            evt = normalizer.build_normalized_event(
                event_id=f"evt_json_{evidence_id}_{idx+1}",
                case_id=case_id,
                evidence_id=evidence_id,
                event_type=str(ev_type),
                category=str(category),
                action=str(action),
                raw_timestamp=raw_time,
                source_format="json",
                parser_name=self.name,
                parser_version=self.version,
                record_locator=locator,
                extraction_run_id=extraction_run_id,
                outcome=str(outcome),
                assumed_tz=assumed_tz,
                username=str(username) if username else None,
                user_id=str(user_id) if user_id else None,
                hostname=str(hostname) if hostname else None,
                device_id=str(device_id) if device_id else None,
                file_name=str(file_name) if file_name else None,
                file_path=str(file_path_val) if file_path_val else None,
                file_sha256=str(file_sha256) if file_sha256 else None,
                device_type=str(dev_type) if dev_type else None,
                device_identifier=str(dev_id) if dev_id else None,
                process_name=str(proc_name) if proc_name else None,
                pid=int(pid) if pid and str(pid).isdigit() else None,
                parent_pid=int(parent_pid) if parent_pid and str(parent_pid).isdigit() else None,
                source_ip=str(src_ip) if src_ip else None,
                destination_ip=str(dst_ip) if dst_ip else None,
                destination_port=int(dst_port) if dst_port and str(dst_port).isdigit() else None,
            )
            events.append(evt)

        return events
