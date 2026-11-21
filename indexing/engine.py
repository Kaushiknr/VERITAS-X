"""Evidence Search and Indexing Engine for VERITAS-X with OpenSearch & Local Offline Support."""
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import httpx
from core.config import settings
from core.models import NormalizedEvent, CanonicalEvidence
from indexing.mappings import (
    EVENTS_INDEX_NAME,
    EVIDENCE_INDEX_NAME,
    EVENTS_MAPPING,
    EVIDENCE_MAPPING,
)

logger = logging.getLogger("veritas.indexing")

class EvidenceSearchEngine:
    """Manages event and evidence indexing, retrieval, and aggregations."""

    def __init__(self, storage_dir: Optional[Path] = None):
        self.storage_dir = storage_dir or (settings.vault_path.parent / "index_storage")
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.events_file = self.storage_dir / "normalized_events.jsonl"
        self.evidence_file = self.storage_dir / "indexed_evidence.jsonl"
        self._opensearch_available: Optional[bool] = None

    def check_opensearch(self) -> bool:
        """Check if OpenSearch is reachable."""
        try:
            with httpx.Client(timeout=1.5) as client:
                res = client.get(
                    settings.opensearch_url,
                    auth=(settings.opensearch_user, settings.opensearch_password),
                    verify=False,
                )
                self._opensearch_available = (res.status_code == 200)
        except Exception:
            self._opensearch_available = False
        return self._opensearch_available

    def initialize_indexes(self) -> None:
        """Ensure indexes exist in OpenSearch if active, or ensure local storage files exist."""
        if not self.events_file.exists():
            self.events_file.touch()
        if not self.evidence_file.exists():
            self.evidence_file.touch()

        if self.check_opensearch():
            try:
                with httpx.Client(timeout=3.0) as client:
                    auth = (settings.opensearch_user, settings.opensearch_password)
                    # Check/create events index
                    res = client.head(f"{settings.opensearch_url}/{EVENTS_INDEX_NAME}", auth=auth, verify=False)
                    if res.status_code == 404:
                        client.put(
                            f"{settings.opensearch_url}/{EVENTS_INDEX_NAME}",
                            json=EVENTS_MAPPING,
                            auth=auth,
                            verify=False,
                        )
                    # Check/create evidence index
                    res = client.head(f"{settings.opensearch_url}/{EVIDENCE_INDEX_NAME}", auth=auth, verify=False)
                    if res.status_code == 404:
                        client.put(
                            f"{settings.opensearch_url}/{EVIDENCE_INDEX_NAME}",
                            json=EVIDENCE_MAPPING,
                            auth=auth,
                            verify=False,
                        )
            except Exception as e:
                logger.warning(f"Could not initialize OpenSearch indexes: {e}")

    def bulk_index_events(self, events: List[NormalizedEvent]) -> int:
        """Store events locally and sync to OpenSearch if available."""
        if not events:
            return 0

        # Always persist locally for offline reproducibility
        with open(self.events_file, "a", encoding="utf-8") as f:
            for evt in events:
                f.write(json.dumps(evt.model_dump()) + "\n")

        # OpenSearch bulk index
        if self.check_opensearch():
            try:
                bulk_lines = []
                for evt in events:
                    meta = {"index": {"_index": EVENTS_INDEX_NAME, "_id": evt.event_id}}
                    bulk_lines.append(json.dumps(meta))
                    bulk_lines.append(json.dumps(evt.model_dump()))
                payload = "\n".join(bulk_lines) + "\n"

                with httpx.Client(timeout=10.0) as client:
                    client.post(
                        f"{settings.opensearch_url}/_bulk",
                        content=payload.encode("utf-8"),
                        headers={"Content-Type": "application/x-ndjson"},
                        auth=(settings.opensearch_user, settings.opensearch_password),
                        verify=False,
                    )
            except Exception as e:
                logger.warning(f"OpenSearch bulk indexing error: {e}")

        return len(events)

    def index_evidence_metadata(self, evidence: CanonicalEvidence) -> None:
        """Record evidence metadata in search index."""
        record = {
            "evidence_id": evidence.evidence_id,
            "case_id": evidence.case_id,
            "original_filename": evidence.identity.original_filename,
            "file_type": evidence.identity.file_type,
            "size_bytes": evidence.identity.size_bytes,
            "original_sha256": evidence.acquisition.original_sha256,
            "stored_sha256": evidence.storage.stored_sha256,
            "integrity_status": evidence.integrity.status,
            "acquired_by": evidence.acquisition.acquired_by,
            "acquired_at": evidence.acquisition.acquired_at,
            "source_system": evidence.acquisition.source_system,
            "parser": evidence.processing.parser,
            "parser_version": evidence.processing.parser_version,
            "processing_status": evidence.processing.status,
        }

        with open(self.evidence_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def search_events(
        self,
        case_id: str,
        query_text: Optional[str] = None,
        event_type: Optional[str] = None,
        device_type: Optional[str] = None,
        username: Optional[str] = None,
        start_time_utc: Optional[str] = None,
        end_time_utc: Optional[str] = None,
        limit: int = 500,
        sort_asc: bool = True,
    ) -> List[NormalizedEvent]:
        """Search and filter normalized events with offline fallback."""
        results: List[NormalizedEvent] = []

        if not self.events_file.exists():
            return results

        q_lower = query_text.lower().strip() if query_text else None

        with open(self.events_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                if data.get("case_id") != case_id:
                    continue

                # Type filter
                if event_type:
                    ev_info = data.get("event", {})
                    if ev_info.get("type") != event_type and ev_info.get("action") != event_type:
                        continue

                # Device type filter
                if device_type:
                    dev_info = data.get("device", {})
                    if dev_info.get("type") != device_type:
                        continue

                # User filter
                if username:
                    act_info = data.get("actor", {})
                    if act_info.get("username") != username:
                        continue

                # Time range filter
                ts = data.get("time", {}).get("timestamp_utc", "")
                if start_time_utc and ts < start_time_utc:
                    continue
                if end_time_utc and ts > end_time_utc:
                    continue

                # Full-text filter
                if q_lower:
                    serialized = json.dumps(data).lower()
                    if q_lower not in serialized:
                        continue

                results.append(NormalizedEvent(**data))

        # Sort chronologically
        results.sort(
            key=lambda e: e.time.timestamp_utc,
            reverse=(not sort_asc),
        )

        return results[:limit]

    def aggregate_events(self, case_id: str) -> Dict[str, Any]:
        """Compute event counts and category distributions."""
        type_counts: Dict[str, int] = {}
        category_counts: Dict[str, int] = {}
        total = 0

        if not self.events_file.exists():
            return {"total_events": 0, "by_type": {}, "by_category": {}}

        with open(self.events_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                if data.get("case_id") != case_id:
                    continue

                total += 1
                ev = data.get("event", {})
                t = ev.get("type", "unknown")
                c = ev.get("category", "unknown")

                type_counts[t] = type_counts.get(t, 0) + 1
                category_counts[c] = category_counts.get(c, 0) + 1

        return {
            "total_events": total,
            "by_type": type_counts,
            "by_category": category_counts,
        }

search_engine = EvidenceSearchEngine()
