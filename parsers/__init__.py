"""Parser Registry and Ingestion Dispatcher for VERITAS-X."""
from pathlib import Path
from typing import List, Optional, Dict, Any
from parsers.base import BaseParser
from parsers.json_parser import JSONSecurityParser
from parsers.csv_parser import CSVForensicParser
from parsers.sysmon_parser import SysmonWindowsParser
from parsers.linux_auth_parser import LinuxAuthParser
from parsers.usb_parser import USBHistoryParser
from core.models import NormalizedEvent

PARSER_REGISTRY: List[BaseParser] = [
    USBHistoryParser(),
    SysmonWindowsParser(),
    LinuxAuthParser(),
    JSONSecurityParser(),
    CSVForensicParser(),
]

def get_parser_for_file(file_path: Path, filename: str) -> Optional[BaseParser]:
    """Identify the matching parser for a given evidence file."""
    for parser in PARSER_REGISTRY:
        if parser.can_parse(file_path, filename):
            return parser
    return None

def parse_evidence_file(
    file_path: Path,
    filename: str,
    case_id: str,
    evidence_id: str,
    extraction_run_id: str,
    options: Optional[Dict[str, Any]] = None,
) -> List[NormalizedEvent]:
    """Dispatch file parsing through the best matching parser."""
    parser = get_parser_for_file(file_path, filename)
    if not parser:
        # Default fallback to JSON if valid json, otherwise CSV
        parser = JSONSecurityParser() if filename.endswith((".json", ".jsonl")) else CSVForensicParser()

    return parser.parse(file_path, case_id, evidence_id, extraction_run_id, options)

__all__ = [
    "BaseParser",
    "JSONSecurityParser",
    "CSVForensicParser",
    "SysmonWindowsParser",
    "LinuxAuthParser",
    "USBHistoryParser",
    "PARSER_REGISTRY",
    "get_parser_for_file",
    "parse_evidence_file",
]
