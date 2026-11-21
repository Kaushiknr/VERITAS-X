"""Sysmon and Windows Security Event Log Parser for VERITAS-X with Native Binary EVTX Support."""
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional
from parsers.base import BaseParser
from core.models import NormalizedEvent
from normalization.normalizer import normalizer

try:
    import Evtx.Evtx as evtx_lib
except ImportError:
    evtx_lib = None

class SysmonWindowsParser(BaseParser):
    name: str = "sysmon_windows_parser"
    version: str = "1.2.0"
    supported_formats: List[str] = ["evtx", "evtx_json", "sysmon_xml", "sysmon_json", "xml"]

    def can_parse(self, file_path: Path, filename: str) -> bool:
        lower = filename.lower()
        if lower.endswith(".evtx") or lower.endswith(".xml"):
            return True
        return "sysmon" in lower or "eventlog" in lower or "security" in lower

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

        # Handle native binary .evtx files
        if ext == ".evtx" and evtx_lib is not None:
            try:
                with evtx_lib.Evtx(str(file_path)) as log:
                    for idx, record in enumerate(log.records(), start=1):
                        try:
                            clean_xml = re.sub(r'xmlns=[^ >]+', '', record.xml())
                            root = ET.fromstring(clean_xml)
                            evt = self._parse_xml_element(root, idx, case_id, evidence_id, extraction_run_id, assumed_tz)
                            if evt:
                                events.append(evt)
                        except Exception:
                            continue
                return events
            except Exception as e:
                print(f"Error parsing binary EVTX: {e}")

        # Handle text JSON or XML export files
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
        except Exception:
            return events

        # JSON EVTX Export
        if content.startswith("{") or content.startswith("["):
            try:
                data = json.loads(content)
                records = data if isinstance(data, list) else data.get("events", [data])
                for idx, r in enumerate(records, start=1):
                    evt = self._parse_json_record(r, idx, case_id, evidence_id, extraction_run_id, assumed_tz)
                    if evt:
                        events.append(evt)
                return events
            except json.JSONDecodeError:
                pass

        # XML EVTX Export
        try:
            xml_str = content if content.startswith("<root") else f"<root>{content}</root>"
            clean_xml = re.sub(r'xmlns=[^ >]+', '', xml_str)
            root = ET.fromstring(clean_xml)
            for idx, elem in enumerate(root.findall(".//Event"), start=1):
                evt = self._parse_xml_element(elem, idx, case_id, evidence_id, extraction_run_id, assumed_tz)
                if evt:
                    events.append(evt)
        except Exception:
            pass

        return events

    def _parse_xml_element(
        self, elem: ET.Element, idx: int, case_id: str, evidence_id: str, run_id: str, tz: str
    ) -> Optional[NormalizedEvent]:
        # Extract System tags
        eid_elem = elem.find(".//EventID")
        event_id_num = 0
        if eid_elem is not None and eid_elem.text:
            try:
                event_id_num = int(eid_elem.text.strip())
            except ValueError:
                pass

        time_created = ""
        tc = elem.find(".//TimeCreated")
        if tc is not None:
            time_created = tc.attrib.get("SystemTime", "")

        computer = ""
        comp = elem.find(".//Computer")
        if comp is not None and comp.text:
            computer = comp.text.strip()

        # Extract EventData key-value pairs
        data: Dict[str, str] = {}
        for d in elem.iter("Data"):
            name = d.attrib.get("Name")
            if name and d.text:
                data[name] = d.text.strip()

        # Classification by Sysmon Event ID
        ev_type = "windows_event"
        category = "system"
        action = f"event_{event_id_num}"

        if event_id_num == 1:
            ev_type = "process_creation"
            category = "process"
            action = "create"
        elif event_id_num == 3:
            ev_type = "network_connection"
            category = "network"
            action = "connect"
        elif event_id_num == 11:
            ev_type = "file_create"
            category = "file_activity"
            action = "create"
        elif event_id_num == 4663:
            ev_type = "file_access"
            category = "file_activity"
            action = "access"

        proc_image = data.get("Image")
        pid_val = data.get("ProcessId")
        file_path = data.get("TargetFilename") or data.get("ObjectName")
        file_name = Path(file_path).name if file_path else (Path(proc_image).name if proc_image else None)

        file_hash = data.get("Hashes")
        if file_hash and "SHA256=" in file_hash:
            for part in file_hash.split(","):
                if "SHA256=" in part:
                    file_hash = part.split("=")[-1].strip()
                    break

        return normalizer.build_normalized_event(
            event_id=f"evt_win_{evidence_id}_{idx}",
            case_id=case_id,
            evidence_id=evidence_id,
            event_type=ev_type,
            category=category,
            action=action,
            raw_timestamp=time_created,
            source_format="windows_evtx",
            parser_name=self.name,
            parser_version=self.version,
            record_locator=f"record:{idx}",
            extraction_run_id=run_id,
            outcome="success",
            assumed_tz=tz,
            hostname=computer,
            file_name=file_name,
            file_path=file_path,
            file_sha256=file_hash,
            process_name=proc_image,
            pid=int(pid_val) if pid_val and str(pid_val).isdigit() else None,
            source_ip=data.get("SourceIp"),
            destination_ip=data.get("DestinationIp"),
            destination_port=int(data.get("DestinationPort")) if str(data.get("DestinationPort", "")).isdigit() else None,
        )

    def _parse_json_record(
        self, r: Dict[str, Any], idx: int, case_id: str, evidence_id: str, run_id: str, tz: str
    ) -> Optional[NormalizedEvent]:
        event_id_num = r.get("event_id") or r.get("EventID") or r.get("id") or 0
        raw_time = r.get("time_created") or r.get("TimeCreated") or r.get("timestamp") or r.get("UtcTime")
        computer = r.get("computer") or r.get("Computer") or r.get("hostname")
        user = r.get("user") or r.get("User") or r.get("username")

        data = r.get("event_data", {})
        if not isinstance(data, dict):
            data = {}

        ev_type = "windows_event"
        category = "system"
        action = f"event_{event_id_num}"
        if event_id_num in [1, "1"]:
            ev_type = "process_creation"
            category = "process"
            action = "create"
        elif event_id_num in [11, "11"]:
            ev_type = "file_create"
            category = "file_activity"
            action = "create"

        proc_name = data.get("Image") or data.get("process_name")
        pid = data.get("ProcessId") or data.get("pid")
        file_path = data.get("TargetFilename") or data.get("file_path")
        file_name = Path(file_path).name if file_path else None

        return normalizer.build_normalized_event(
            event_id=f"evt_win_{evidence_id}_{idx}",
            case_id=case_id,
            evidence_id=evidence_id,
            event_type=ev_type,
            category=category,
            action=action,
            raw_timestamp=raw_time,
            source_format="windows_evtx",
            parser_name=self.name,
            parser_version=self.version,
            record_locator=f"event_record:{idx}",
            extraction_run_id=run_id,
            outcome="success",
            assumed_tz=tz,
            username=user,
            hostname=computer,
            file_name=file_name,
            file_path=file_path,
            process_name=proc_name,
            pid=int(pid) if pid and str(pid).isdigit() else None,
        )
