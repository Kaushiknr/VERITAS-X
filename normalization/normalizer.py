"""Forensic Event Normalization Engine for VERITAS-X."""
from datetime import datetime, timezone
import re
from typing import Optional, Tuple, Dict, Any
from core.models import (
    NormalizedEvent,
    EventAction,
    EventTime,
    EventActor,
    EventHost,
    EventFile,
    EventDevice,
    EventProcess,
    EventNetwork,
    EventSource,
    EventProvenance,
)

class EventNormalizer:
    """Normalizes raw forensic artifacts into canonical event representations."""

    NORMALIZATION_VERSION = "1.0.0"

    @staticmethod
    def normalize_timestamp(raw_time: Any, assumed_tz: str = "UTC") -> Tuple[str, str, str]:
        """
        Convert various timestamp representations into UTC ISO8601.
        Returns (timestamp_utc, original_string, timezone_string).
        """
        orig_str = str(raw_time).strip()
        if not orig_str or orig_str.lower() in ("none", "null", ""):
            now_utc = datetime.now(timezone.utc).isoformat()
            return now_utc, "N/A", "UTC"

        # Check for numeric unix timestamp (seconds or milliseconds)
        try:
            val = float(orig_str)
            if val > 1e11:  # Milliseconds
                dt = datetime.fromtimestamp(val / 1000.0, tz=timezone.utc)
            else:  # Seconds
                dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt.isoformat(), orig_str, "UTC"
        except (ValueError, OverflowError):
            pass

        # Clean common ISO variants (e.g., replace Z with +00:00)
        iso_candidate = orig_str.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(iso_candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.isoformat(), orig_str, str(assumed_tz)
        except ValueError:
            pass

        # Try common log formats
        common_formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%d/%m/%Y %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%b %d %H:%M:%S",  # Syslog (e.g., Nov 21 08:30:00)
        ]

        current_year = datetime.now(timezone.utc).year
        for fmt in common_formats:
            try:
                dt = datetime.strptime(orig_str, fmt)
                if "%Y" not in fmt:
                    dt = dt.replace(year=current_year)
                dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat(), orig_str, assumed_tz
            except ValueError:
                continue

        # Fallback if unparseable: record current time as UTC, preserve original
        now_utc = datetime.now(timezone.utc).isoformat()
        return now_utc, orig_str, assumed_tz

    def build_normalized_event(
        self,
        event_id: str,
        case_id: str,
        evidence_id: str,
        event_type: str,
        category: str,
        action: str,
        raw_timestamp: Any,
        source_format: str,
        parser_name: str,
        parser_version: str,
        record_locator: str,
        extraction_run_id: str,
        outcome: str = "unknown",
        assumed_tz: str = "UTC",
        username: Optional[str] = None,
        user_id: Optional[str] = None,
        hostname: Optional[str] = None,
        device_id: Optional[str] = None,
        file_name: Optional[str] = None,
        file_path: Optional[str] = None,
        file_sha256: Optional[str] = None,
        device_type: Optional[str] = None,
        device_identifier: Optional[str] = None,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        parent_pid: Optional[int] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        destination_port: Optional[int] = None,
    ) -> NormalizedEvent:
        """Construct a validated NormalizedEvent."""
        ts_utc, orig_ts, tz = self.normalize_timestamp(raw_timestamp, assumed_tz)

        return NormalizedEvent(
            event_id=event_id,
            schema_version="1.0.0",
            case_id=case_id,
            evidence_id=evidence_id,
            event=EventAction(
                type=event_type,
                category=category,
                action=action,
                outcome=outcome,
            ),
            time=EventTime(
                original=orig_ts,
                timezone=tz,
                timestamp_utc=ts_utc,
                precision="second",
            ),
            actor=EventActor(
                user_id=user_id,
                username=username,
            ),
            host=EventHost(
                hostname=hostname,
                device_id=device_id,
            ),
            file=EventFile(
                name=file_name,
                path=file_path,
                sha256=file_sha256,
            ),
            device=EventDevice(
                type=device_type,
                identifier=device_identifier,
            ),
            process=EventProcess(
                name=process_name,
                pid=pid,
                parent_pid=parent_pid,
            ),
            network=EventNetwork(
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
            ),
            source=EventSource(
                format=source_format,
                parser=parser_name,
                parser_version=parser_version,
                record_locator=record_locator,
            ),
            provenance=EventProvenance(
                extraction_run_id=extraction_run_id,
                normalization_version=self.NORMALIZATION_VERSION,
            ),
        )

normalizer = EventNormalizer()
