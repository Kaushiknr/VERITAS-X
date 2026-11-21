"""CSV Forensic Log Parser for VERITAS-X."""
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional
from parsers.base import BaseParser
from core.models import NormalizedEvent
from normalization.normalizer import normalizer

class CSVForensicParser(BaseParser):
    name: str = "csv_forensic_parser"
    version: str = "1.0.0"
    supported_formats: List[str] = ["csv", "tsv"]

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
        delimiter = "\t" if file_path.suffix.lower() == ".tsv" else ","

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f, delimiter=delimiter)
            for row_no, row in enumerate(reader, start=1):
                clean_row = {k.strip().lower(): (v.strip() if v else "") for k, v in row.items() if k}

                # Find timestamp
                raw_time = (
                    clean_row.get("timestamp")
                    or clean_row.get("time")
                    or clean_row.get("datetime")
                    or clean_row.get("date_time")
                    or clean_row.get("date")
                )

                # Event type / action
                ev_type = (
                    clean_row.get("event_type")
                    or clean_row.get("type")
                    or clean_row.get("action")
                    or clean_row.get("activity")
                    or "csv_record"
                )
                category = clean_row.get("category") or "log"
                action = clean_row.get("action") or ev_type
                outcome = clean_row.get("outcome") or clean_row.get("status") or "unknown"

                # Actor
                username = clean_row.get("username") or clean_row.get("user") or clean_row.get("account")
                user_id = clean_row.get("user_id")

                # Host
                hostname = clean_row.get("hostname") or clean_row.get("host") or clean_row.get("computer")
                device_id = clean_row.get("device_id")

                # File
                file_name = clean_row.get("filename") or clean_row.get("file_name") or clean_row.get("file")
                file_path_val = clean_row.get("filepath") or clean_row.get("file_path") or clean_row.get("path")
                file_sha256 = clean_row.get("sha256") or clean_row.get("hash") or clean_row.get("file_hash")

                # Device
                dev_type = clean_row.get("device_type")
                dev_id = clean_row.get("device_identifier") or clean_row.get("target_device") or clean_row.get("device_id")

                # Process
                proc_name = clean_row.get("process_name") or clean_row.get("process") or clean_row.get("image")
                pid = clean_row.get("pid")
                parent_pid = clean_row.get("parent_pid")

                # Network
                src_ip = clean_row.get("source_ip") or clean_row.get("src_ip")
                dst_ip = clean_row.get("destination_ip") or clean_row.get("dst_ip")
                dst_port = clean_row.get("destination_port") or clean_row.get("dst_port")

                evt = normalizer.build_normalized_event(
                    event_id=f"evt_csv_{evidence_id}_{row_no}",
                    case_id=case_id,
                    evidence_id=evidence_id,
                    event_type=str(ev_type),
                    category=str(category),
                    action=str(action),
                    raw_timestamp=raw_time,
                    source_format="csv",
                    parser_name=self.name,
                    parser_version=self.version,
                    record_locator=f"row:{row_no}",
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
