"""Linux /var/log/auth.log Parser for VERITAS-X with Real OpenSSH & PAM Event Support."""
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from parsers.base import BaseParser
from core.models import NormalizedEvent
from normalization.normalizer import normalizer

class LinuxAuthParser(BaseParser):
    name: str = "linux_auth_parser"
    version: str = "1.2.0"
    supported_formats: List[str] = ["auth_log", "secure_log", "log", "ssh_log"]

    # Pattern 1: Accepted login
    SSH_ACCEPTED_RE = re.compile(
        r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+([\w\.\-]+)\s+sshd\[(\d+)\]:\s+Accepted\s+(\w+)\s+for\s+(\w+)\s+from\s+([\d\.]+)\s+port\s+(\d+)",
        re.IGNORECASE,
    )
    # Pattern 2: Failed password
    SSH_FAILED_RE = re.compile(
        r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+([\w\.\-]+)\s+sshd\[(\d+)\]:\s+Failed\s+(?:password|publickey)\s+for\s+(?:invalid\s+user\s+)?(\w+)\s+from\s+([\d\.]+)\s+port\s+(\d+)",
        re.IGNORECASE,
    )
    # Pattern 3: Invalid user probe
    SSH_INVALID_RE = re.compile(
        r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+([\w\.\-]+)\s+sshd\[(\d+)\]:\s+Invalid\s+user\s+(\w+)\s+from\s+([\d\.]+)",
        re.IGNORECASE,
    )
    # Pattern 4: Possible break-in attempt / reverse mapping failure
    SSH_BREAKIN_RE = re.compile(
        r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+([\w\.\-]+)\s+sshd\[(\d+)\]:\s+reverse\s+mapping\s+checking\s+getaddrinfo.*?\[([\d\.]+)\].*?(POSSIBLE BREAK-IN ATTEMPT)",
        re.IGNORECASE,
    )
    # Pattern 5: Sudo command execution
    SUDO_RE = re.compile(
        r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+([\w\.\-]+)\s+sudo(?:\[(\d+)\])?:\s+(\w+)\s+:\s+TTY=.*?COMMAND=(.*)$",
        re.IGNORECASE,
    )

    def can_parse(self, file_path: Path, filename: str) -> bool:
        lower = filename.lower()
        return "auth" in lower or "secure" in lower or "ssh" in lower or "linux" in lower or lower.endswith(".log")

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
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                # 1. Accepted Login
                m = self.SSH_ACCEPTED_RE.match(line)
                if m:
                    ts, host, pid, method, user, src_ip, src_port = m.groups()
                    events.append(normalizer.build_normalized_event(
                        event_id=f"evt_auth_{evidence_id}_{line_no}",
                        case_id=case_id,
                        evidence_id=evidence_id,
                        event_type="authentication_success",
                        category="identity",
                        action="login",
                        raw_timestamp=ts,
                        source_format="linux_auth_log",
                        parser_name=self.name,
                        parser_version=self.version,
                        record_locator=f"line:{line_no}",
                        extraction_run_id=extraction_run_id,
                        outcome="success",
                        assumed_tz=assumed_tz,
                        username=user,
                        hostname=host,
                        process_name="sshd",
                        pid=int(pid),
                        source_ip=src_ip,
                        destination_port=int(src_port),
                    ))
                    continue

                # 2. Failed Password
                m = self.SSH_FAILED_RE.match(line)
                if m:
                    ts, host, pid, user, src_ip, src_port = m.groups()
                    events.append(normalizer.build_normalized_event(
                        event_id=f"evt_auth_{evidence_id}_{line_no}",
                        case_id=case_id,
                        evidence_id=evidence_id,
                        event_type="authentication_failure",
                        category="identity",
                        action="failed_password",
                        raw_timestamp=ts,
                        source_format="linux_auth_log",
                        parser_name=self.name,
                        parser_version=self.version,
                        record_locator=f"line:{line_no}",
                        extraction_run_id=extraction_run_id,
                        outcome="failure",
                        assumed_tz=assumed_tz,
                        username=user,
                        hostname=host,
                        process_name="sshd",
                        pid=int(pid),
                        source_ip=src_ip,
                        destination_port=int(src_port),
                    ))
                    continue

                # 3. Invalid User Probe
                m = self.SSH_INVALID_RE.match(line)
                if m:
                    ts, host, pid, user, src_ip = m.groups()
                    events.append(normalizer.build_normalized_event(
                        event_id=f"evt_auth_{evidence_id}_{line_no}",
                        case_id=case_id,
                        evidence_id=evidence_id,
                        event_type="authentication_failure",
                        category="identity",
                        action="invalid_user_probe",
                        raw_timestamp=ts,
                        source_format="linux_auth_log",
                        parser_name=self.name,
                        parser_version=self.version,
                        record_locator=f"line:{line_no}",
                        extraction_run_id=extraction_run_id,
                        outcome="failure",
                        assumed_tz=assumed_tz,
                        username=user,
                        hostname=host,
                        process_name="sshd",
                        pid=int(pid),
                        source_ip=src_ip,
                    ))
                    continue

                # 4. Break-in Alert
                m = self.SSH_BREAKIN_RE.match(line)
                if m:
                    ts, host, pid, src_ip, alert_text = m.groups()
                    events.append(normalizer.build_normalized_event(
                        event_id=f"evt_auth_{evidence_id}_{line_no}",
                        case_id=case_id,
                        evidence_id=evidence_id,
                        event_type="suspicious_activity",
                        category="security",
                        action="possible_break_in",
                        raw_timestamp=ts,
                        source_format="linux_auth_log",
                        parser_name=self.name,
                        parser_version=self.version,
                        record_locator=f"line:{line_no}",
                        extraction_run_id=extraction_run_id,
                        outcome="alert",
                        assumed_tz=assumed_tz,
                        hostname=host,
                        process_name="sshd",
                        pid=int(pid),
                        source_ip=src_ip,
                    ))
                    continue

                # 5. Sudo Execution
                m = self.SUDO_RE.match(line)
                if m:
                    ts, host, pid, user, cmd = m.groups()
                    events.append(normalizer.build_normalized_event(
                        event_id=f"evt_auth_{evidence_id}_{line_no}",
                        case_id=case_id,
                        evidence_id=evidence_id,
                        event_type="privilege_elevation",
                        category="process",
                        action="sudo_command",
                        raw_timestamp=ts,
                        source_format="linux_auth_log",
                        parser_name=self.name,
                        parser_version=self.version,
                        record_locator=f"line:{line_no}",
                        extraction_run_id=extraction_run_id,
                        outcome="success",
                        assumed_tz=assumed_tz,
                        username=user,
                        hostname=host,
                        process_name=cmd.strip(),
                        pid=int(pid) if pid else None,
                    ))

        return events
