"""Unit Tests for Forensic Parsers."""
import tempfile
import json
from pathlib import Path
from parsers.json_parser import JSONSecurityParser
from parsers.csv_parser import CSVForensicParser
from parsers.sysmon_parser import SysmonWindowsParser
from parsers.linux_auth_parser import LinuxAuthParser
from parsers.usb_parser import USBHistoryParser

def test_json_security_parser():
    parser = JSONSecurityParser()
    data = [
        {
            "event_type": "file_access",
            "category": "file_activity",
            "action": "access",
            "timestamp": "2026-11-21T09:00:00Z",
            "username": "jsmith",
            "hostname": "LAB-PC-01",
            "file": {"name": "confidential.pdf", "path": "/docs/confidential.pdf"},
        }
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = Path(f.name)

    events = parser.parse(path, "case_1", "ev_1", "run_1")
    assert len(events) == 1
    assert events[0].event.type == "file_access"
    assert events[0].actor.username == "jsmith"
    assert events[0].file.name == "confidential.pdf"
    path.unlink()

def test_csv_forensic_parser():
    parser = CSVForensicParser()
    csv_content = (
        "timestamp,event_type,username,hostname,filename\n"
        "2026-11-21 09:05:00,file_create,jsmith,LAB-PC-01,secret.docx\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        f.write(csv_content)
        path = Path(f.name)

    events = parser.parse(path, "case_1", "ev_2", "run_1")
    assert len(events) == 1
    assert events[0].event.type == "file_create"
    assert events[0].file.name == "secret.docx"
    path.unlink()

def test_usb_history_parser():
    parser = USBHistoryParser()
    usb_data = {
        "usb_devices": [
            {
                "connected_at": "2026-11-21T08:55:00Z",
                "serial_number": "USB-SANDISK-999",
                "vendor": "SanDisk Ultra",
                "hostname": "LAB-PC-01",
                "action": "usb_connection",
            }
        ]
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(usb_data, f)
        path = Path(f.name)

    events = parser.parse(path, "case_1", "ev_3", "run_1")
    assert len(events) == 1
    assert events[0].event.type == "usb_connection"
    assert events[0].device.identifier == "USB-SANDISK-999"
    path.unlink()
